import { randomUUID } from 'node:crypto'
import type { AddressInfo } from 'node:net'

import { redisClient } from '@axiumine/koa-utils/dataSources/Redis'
import { REFRESH_TOKEN_EXPIRY } from '@axiumine/koa-utils/lib/tokens'
import { encryptDocument } from '@axiumine/marketplace-common/encryption/encryptDocument'
import { ENCRYPTED_FIELDS_USER, KEY_ALT_NAME_USER } from '@axiumine/marketplace-common/encryption/encryptedFields'
import { hashSessionToken } from '@axiumine/marketplace-common/others/hashSessionToken'
import { REFRESH_ATTEMPT_BUCKET, REFRESH_FAMILY_BUCKET } from '@axiumine/marketplace-common/others/refreshRateLimit'
import { familyKey, sessionKey, tombstoneKey } from '@axiumine/marketplace-common/others/sessionKeys'
import { sha256Hex } from '@axiumine/marketplace-common/others/sha256Hex'
import { TIER } from '@axiumine/marketplace-common/others/Tier'
import * as dotenv from 'dotenv'
import type { Server } from 'http'
import Keygrip from 'keygrip'
import mongoose from 'mongoose'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The sources call dotenv.config() transitively (MongoDB/Redis datasources, handler); this is a
// belt-and-suspenders load so REDIS_* and MONGODB_URI are present when this file's top level reads them.
dotenv.config()

import { ENDPOINT, start } from '../../src/index.mts'
import { ITEST_KEYGRIP_KEYS } from '../../vitest.keygrip.mts'

const REDIS_KEY = process.env.REDIS_KEY as string
const INTROSPECTION_CODE = process.env.INTROSPECTION_CODE as string

// accessTokenExpiry() returns floor((random() * 61 + 30) * 60) — a random 30-to-91-minute
// window — so the access TTL can only be asserted as a range. REFRESH_TOKEN_EXPIRY is fixed.
const ACCESS_TTL_MIN = 1800
const ACCESS_TTL_MAX = 5459

// Nothing on this tier ever verifies a password — the login lives on 4028 — so a seeded hash only
// has to satisfy the validator's exactly-60-characters rule.
const PASSWORD_HASH = `$2y$14$${'x'.repeat(53)}`
// Must match the server's cookie signer exactly (see createServer): same keys, same SHA-512.
const keys = new Keygrip(
	ITEST_KEYGRIP_KEYS.map((key) => key.material),
	'sha512'
)

// A refresh cookie the way Koa emits it: the value plus its `.sig` Keygrip signature.
function signedCookie(refresh: string): string {
	return `refresh_token=${refresh}; refresh_token.sig=${keys.sign(`refresh_token=${refresh}`)}`
}

// The introspection code is NOT a substitute for the cookie: verifySignedRefreshToken runs first
// and rejects a request with no cookie before the code is ever read. The bypass only rescues a
// correctly signed cookie whose Redis session no longer exists — so service-to-service calls send
// both. Every headers object below reflects that ordering.
function bypassHeaders() {
	return { cookie: signedCookie(randomUUID()), 'x-introspectioncode': INTROSPECTION_CODE }
}

let keygripWatch: NodeJS.Timeout
let keygripSubscriber: { close(): Promise<unknown> }

let httpServer: Server
let base: string

/** POST a GraphQL document to the real endpoint and return status + parsed body. */
async function gql(query: string, headers: Record<string, string> = {}) {
	const res = await fetch(`${base}${ENDPOINT}`, {
		method: 'POST',
		headers: { 'content-type': 'application/json', ...headers },
		body: JSON.stringify({ query })
	})

	return {
		status: res.status,
		setCookie: res.headers.getSetCookie(),
		// tdwKoaErrorHandler answers rejected requests with {message, description}; Apollo answers
		// accepted ones with {data, errors}. One parse covers both shapes.
		json: (await res.json()) as {
			data?: Record<string, unknown>
			errors?: Array<{ message: string }>
			message?: string
			description?: string
		}
	}
}

/****************************************************************************************
 * Seeds. The rotation test needs the handler's MongoDB lookup to succeed, so it writes a
 * real customer to the dev database. Every document carries an `itest-…@marketplace.invalid`
 * address and is deleted again in afterAll, as is every session key it leaves on the cluster.
 ****************************************************************************************/

const seededIds: mongoose.Types.ObjectId[] = []
const seededKeys: string[] = []

/** The raw driver handle — only defined once start() has connected. */
function db() {
	return mongoose.connection.db!
}

/** Remember a session key so afterAll removes it even if the test that created it fails. */
function track(key: string) {
	seededKeys.push(key)

	return key
}

/**
 * Inserted with the raw driver rather than the Mongoose model: the collection validator is
 * `additionalProperties: false` and owns the field shape, so writing through it directly keeps the
 * seed honest about what the server really accepts.
 *
 * ⚠️ `registeredAt` is here because it is one of the collection's only two required fields, and
 * `personalData` is absent because it is *not* one of them — a customer registers with an email and
 * a password and fills the rest in later, which is the divergence from `shopOwner` this seed has to
 * respect or the validator refuses the insert.
 *
 * ⚠️ `login.email` goes through `encryptDocument` first (ADR-029): the collection declares it
 * `binData`, so a raw seed of plaintext is refused by the validator. `registeredAt` and the
 * `disabled` / `deleted` flags the state-gate tests add are not personal data and stay in the clear.
 */
async function seedUser(overrides: Record<string, unknown> = {}) {
	const email = `itest-${randomUUID()}@marketplace.invalid`
	const _id = new mongoose.Types.ObjectId()

	await db()
		.collection('user')
		.insertOne(
			await encryptDocument(
				{
					_id,
					login: { email, password: PASSWORD_HASH },
					registeredAt: new Date(),
					...overrides
				},
				ENCRYPTED_FIELDS_USER,
				KEY_ALT_NAME_USER
			)
		)
	seededIds.push(_id)

	return { _id, email }
}

/**
 * The three lineage fields a real login stamps (E14-S01), and which `assertRefreshLineage` refuses a
 * session without — so, exactly like `tier`, a seed missing them is refused at the guard and every test
 * past it would fail for a reason unrelated to what it asserts.
 *
 * The defaults describe a session opened just now with thirty days of rotations ahead of it, so nothing
 * in this file trips the absolute cap by accident.
 */
function sessionLineage(over: Record<string, string> = {}) {
	return { familyId: randomUUID(), originalLogin: `${Date.now()}`, sessionCapDays: '30', ...over }
}

/**
 * The key a rate-limit counter lives under (E14-S08). Derived rather than written out as a literal,
 * because the identities here are random per run — but the bucket names come from the policy file
 * itself, so a renamed bucket fails this suite instead of quietly counting nothing.
 */
function rateLimitKey(bucket: string, identity: string) {
	return `${process.env.REDIS_KEY}rl:${bucket}:${sha256Hex(identity)}`
}

/**
 * Seed a live refresh session pointing at `_id` and assert the request it carries is refused. Both
 * checkUserAuthorizationDisDel cases below reduce to exactly this and differ only in how the user
 * document was seeded, so the session-plus-assertion half is shared rather than written twice.
 */
async function expectRefreshRejected(_id: mongoose.Types.ObjectId) {
	const refresh = randomUUID()
	await redisClient.hSet(track(sessionKey(`refresh:${refresh}`)), {
		_id: _id.toHexString(),
		tier: TIER.user,
		...sessionLineage()
	})

	const { status, json } = await gql('{ helloRefresh { txt } }', { cookie: signedCookie(refresh) })

	expect(status).toBe(401)
	expect(json.message).toBe('Unauthorized')
}

/** The refresh token Koa just set, read back out of the Set-Cookie headers. */
function refreshTokenFrom(setCookie: string[]) {
	const header = setCookie.find((cookie) => cookie.startsWith('refresh_token='))
	if (!header) throw new Error('refresh did not set a refresh_token cookie')

	return header.slice('refresh_token='.length).split(';')[0]
}

beforeAll(async () => {
	const server = await start()
	if (!server) throw new Error('server failed to start against the real Redis cluster / MongoDB')
	httpServer = server.httpServer
	// Both belong to the live key watch (ADR-034), and both have to be handed back for the drain below:
	// the timer is unref'd but still fires while the suite runs, and the subscriber is a second
	// connection nothing else in this file knows about.
	keygripWatch = server.keygripWatch
	keygripSubscriber = server.keygripSubscriber
	const address = httpServer.address() as AddressInfo | null
	if (!address || typeof address === 'string') throw new Error('no TCP address on the booted server')
	base = `http://127.0.0.1:${address.port}`
})

/**
 * Cleanup must never abort halfway. `afterAll` drains MongoDB first and Redis second, so a single
 * failed delete — a cluster MOVED mid-resharding, a handle closed early — would otherwise strand
 * every id and key registered after it, and would skip the Redis drain entirely. Mongo residue is
 * harmless, globalSetup drops and re-migrates the database on the next run; a stranded Redis key
 * sits in the cluster for its whole TTL, which for a refresh session is 90 days.
 */
async function drainSafely(what: string, remove: () => Promise<unknown>) {
	try {
		await remove()
	} catch (error) {
		console.error(`[afterAll] cleanup failed for ${what}:`, error)
	}
}

afterAll(async () => {
	// Drop whatever this run created while the handles are still open: documents first, then
	// any session key. One del per key — this is a cluster, so a multi-key del would CROSSSLOT.
	for (const _id of seededIds) {
		await drainSafely(`user ${_id.toString()}`, () => db().collection('user').deleteOne({ _id }))
	}
	for (const key of seededKeys) {
		await drainSafely(key, () => redisClient.del(key))
	}

	// The watch first: a poll that fires against a closing client would report an error nobody caused.
	clearInterval(keygripWatch)
	await drainSafely('keygrip subscriber', () => keygripSubscriber.close())

	await new Promise<void>((resolve) => httpServer.close(() => resolve()))
	await redisClient.close()
	await mongoose.disconnect()
})

describe('user-authenticated-authorization service (integration, real MongoDB + real Redis cluster)', () => {
	// start() is what wires both datasources; asserting the live handles is what makes the rest of
	// this file an integration suite rather than an in-process schema test.
	it('has a live MongoDB connection', () => {
		expect(mongoose.connection.readyState).toBe(1)
	})

	it('has a live Redis cluster connection, round-tripping a key in the isolated namespace', async () => {
		const key = `${REDIS_KEY}ping:${randomUUID()}`

		// EX so this one cannot outlive the run. It is never registered for the afterAll drain, so
		// without a TTL a hard kill — or a throw on the assertion below — strands it on the cluster
		// forever. 60s is far longer than the round trip and short enough to be self-cleaning.
		await redisClient.set(key, 'pong', { EX: 60 })
		expect(await redisClient.get(key)).toBe('pong')

		await redisClient.del(key)
		expect(await redisClient.get(key)).toBeNull()
	})
})

describe('refresh-cookie gate over HTTP', () => {
	it('answers 412 when the request carries no cookie at all', async () => {
		const { status, json } = await gql('{ helloRefresh { txt } }')

		expect(status).toBe(412)
		expect(json.message).toBe('Precondition Failed')
	})

	it('answers 401 when the Keygrip signature does not verify', async () => {
		const { status, json } = await gql('{ helloRefresh { txt } }', {
			cookie: `refresh_token=${randomUUID()}; refresh_token.sig=forged`
		})

		expect(status).toBe(401)
		expect(json.message).toBe('Unauthorized')
	})

	it('answers 498 when the signature is good but the session is gone from Redis', async () => {
		const { status, json } = await gql('{ helloRefresh { txt } }', { cookie: signedCookie(randomUUID()) })

		expect(status).toBe(498)
		expect(json.message).toBe('Invalid Token')
	})

	// The session really exists on the cluster, so the request gets past Redis and dies in MongoDB:
	// the _id it points at matches no user. This is the one case that exercises both datasources in
	// a single request, which no unit test can do.
	it('answers 401 when the live session points at a user MongoDB does not have', async () => {
		const refresh = randomUUID()
		const refreshKey = sessionKey(`refresh:${refresh}`)
		await redisClient.hSet(refreshKey, {
			_id: new mongoose.Types.ObjectId().toHexString(),
			tier: TIER.user,
			...sessionLineage()
		})

		try {
			const { status, json } = await gql('{ helloRefresh { txt } }', { cookie: signedCookie(refresh) })

			expect(status).toBe(401)
			expect(json.message).toBe('Unauthorized')
		} finally {
			await redisClient.del(refreshKey)
		}
	})

	/*
	 * ⚠️ A session minted by another tier, refused by the tier assertion rather than by the lookup.
	 *
	 * All nine services share one `REDIS_KEY`, so this hash is byte-for-byte something the ShopOwner
	 * authorization service would accept — and before `tier` was written into the session, this
	 * service accepted it too. The document it names really is a `user`, so nothing downstream would
	 * have noticed; the mismatch is the only thing that can reject it.
	 *
	 * 403 and not 401, which is the whole point of the distinction: the caller authenticated
	 * correctly, it simply authenticated somewhere else. A 401 would tell the client to refresh its
	 * way out — and this *is* the refresh call, so there is nothing left for it to try.
	 */
	it('answers 403 when the live session was minted for another tier', async () => {
		const { _id } = await seedUser()
		const refresh = randomUUID()
		await redisClient.hSet(track(sessionKey(`refresh:${refresh}`)), {
			_id: _id.toHexString(),
			tier: TIER.shopOwner,
			...sessionLineage()
		})

		const { status, json } = await gql('{ helloRefresh { txt } }', { cookie: signedCookie(refresh) })

		expect(status).toBe(403)
		expect(json.message).toBe('Forbidden')
	})

	// The other MongoDB branch tokenInfoUser can take once it DOES find the document: a real
	// customer, accepted by the real validator, that checkUserAuthorizationDisDel must reject. The
	// unit suite only proves the handler propagates whatever that gate throws — it mocks the gate
	// itself — so this is the one test that proves the real marketplace-common gate actually rejects
	// a `disabled: true` document read back out of the real database, not a stub standing in for it.
	it('answers 401 when the live session points at a user MongoDB has marked disabled', async () => {
		const { _id } = await seedUser({ disabled: true })
		// Read the seed back through the raw driver before the request runs: without this, a 401
		// here would be equally consistent with the insert having silently failed (tokenInfoUser's
		// own null-document branch throws the exact same throwUnauthorizedError()), which would prove
		// nothing about checkUserAuthorizationDisDel at all.
		expect(await db().collection('user').findOne({ _id })).toMatchObject({ disabled: true })

		await expectRefreshRejected(_id)
	})

	// Same gate, the other trigger. `deleted` is a Date in the real validator (a soft-delete
	// timestamp), not a boolean like `disabled` — seeding a real Date and watching the request
	// still land in the same 401 is what proves the validator's field type and the gate's `if
	// (deleted)` check agree, which a hand-rolled mock has no way to check.
	it('answers 401 when the live session points at a user MongoDB has marked deleted', async () => {
		const { _id } = await seedUser({ deleted: new Date() })
		// Same reasoning as the disabled case above: confirm the write really landed, and landed with
		// a `deleted` field the validator actually accepted, before treating the 401 below as proof
		// of anything about the gate rather than a masked seed failure.
		const seeded = await db().collection('user').findOne({ _id })
		expect(seeded?.deleted).toBeInstanceOf(Date)

		await expectRefreshRejected(_id)
	})
})

describe('refresh rotates the session on the cluster', () => {
	const mutation = 'mutation { refresh { status accessToken } }'

	it('writes the new pair, arms both TTLs, and deletes the refresh token it consumed', async () => {
		const { _id, email } = await seedUser()
		const lineage = sessionLineage()
		const oldRefresh = randomUUID()
		const oldRefreshKey = track(sessionKey(`refresh:${oldRefresh}`))
		// A rotation writes two keys of its own beyond the new pair — the lineage's family set and the
		// consumed token's tombstone, both with the refresh token's own 90-day TTL — so both are
		// registered for the drain here, before the call that creates them, rather than after it.
		const keyFamily = track(familyKey(lineage.familyId))
		const keyTombstone = track(tombstoneKey(`refresh:${oldRefresh}`))
		await redisClient.hSet(oldRefreshKey, { _id: _id.toHexString(), tier: TIER.user, ...lineage })

		const { status, json, setCookie } = await gql(mutation, { cookie: signedCookie(oldRefresh) })

		expect(status).toBe(200)
		expect(json.errors).toBeUndefined()

		// A 200 means the rotation already wrote both keys on the cluster, so they are registered
		// here rather than after the assertions below — a failing expect would otherwise strand the
		// new refresh hash for its whole 90-day TTL.
		const refreshed = json.data?.refresh as { status: boolean; accessToken: string }
		const accessKey = track(sessionKey(`access:${refreshed.accessToken}`))
		const newRefreshKey = track(sessionKey(`refresh:${refreshTokenFrom(setCookie)}`))

		expect(refreshed.status).toBe(true)
		expect(refreshed.accessToken).not.toBe('')
		expect(newRefreshKey).not.toBe(oldRefreshKey)

		// The handler rebuilt ctx.state.user out of Redis + MongoDB and the resolver strips
		// refreshToken back off it. IRedisDataUser carries no onboarding fields — unlike the
		// shopOwner tier — so the customer access hash is exactly {_id, email, tier}.
		expect(await redisClient.hGetAll(accessKey)).toEqual({ _id: _id.toHexString(), email, tier: TIER.user })
		// The lineage rides through the rotation unchanged — a family or a login date minted afresh here
		// would hand the session an unlimited life one refresh at a time.
		expect(await redisClient.hGetAll(newRefreshKey)).toEqual({ _id: _id.toHexString(), tier: TIER.user, ...lineage })

		// Both expire() calls really ran, and ran *after* the hSet. A key whose TTL was armed
		// before its fields would read -1 here.
		const accessTtl = await redisClient.ttl(accessKey)
		expect(accessTtl).toBeGreaterThanOrEqual(ACCESS_TTL_MIN - 5)
		expect(accessTtl).toBeLessThanOrEqual(ACCESS_TTL_MAX)
		expect(await redisClient.ttl(newRefreshKey)).toBeGreaterThan(REFRESH_TOKEN_EXPIRY - 60)

		// One refresh token, one use.
		expect(await redisClient.hGetAll(oldRefreshKey)).toEqual({})

		// ⚠️ And the use left a marker (E14-S02). Without it a replay of the token just consumed is
		// indistinguishable from ordinary expiry, which is the whole difference between "your session
		// ended" and "someone else is holding your refresh token".
		const tombstone = await redisClient.hGetAll(keyTombstone)
		expect(tombstone.familyId).toBe(lineage.familyId)
		expect(Number(tombstone.consumedAt)).toBeGreaterThan(Date.now() - 60_000)
		expect(await redisClient.ttl(keyTombstone)).toBeGreaterThan(REFRESH_TOKEN_EXPIRY - 60)

		// Both halves of the new pair are filed into the family the old session belonged to, which is
		// what a revocation walks when this token is replayed.
		expect((await redisClient.sMembers(keyFamily)).sort()).toEqual([accessKey, newRefreshKey].sort())
		expect(await redisClient.ttl(keyFamily)).toBeGreaterThan(REFRESH_TOKEN_EXPIRY - 60)
	})

	/*
	 * E14-S08 on the cluster, both buckets in one call. The per-token counter is armed by this service's
	 * own middleware before the session is read; the per-family one by `refreshSessionTokens` as it mints.
	 * A rotation that really happened must leave exactly one attempt and one mint counted.
	 *
	 * ⚠️ Neither counter may name the token or the key its session lives under. That is what the two
	 * `not.toContain` lines below are for: a limiter that keyed on the token itself would put a live
	 * credential into a key that outlives the request and is trivially listed by any operator.
	 */
	it('counts the attempt and the mint in their own two buckets', async () => {
		const { _id } = await seedUser()
		const lineage = sessionLineage()
		const oldRefresh = randomUUID()
		const oldRefreshKey = track(sessionKey(`refresh:${oldRefresh}`))
		track(familyKey(lineage.familyId))
		track(tombstoneKey(`refresh:${oldRefresh}`))
		const attemptKey = track(rateLimitKey(REFRESH_ATTEMPT_BUCKET, hashSessionToken(`refresh:${oldRefresh}`)))
		const mintKey = track(rateLimitKey(REFRESH_FAMILY_BUCKET, lineage.familyId))
		await redisClient.hSet(oldRefreshKey, { _id: _id.toHexString(), tier: TIER.user, ...lineage })

		const { status, json, setCookie } = await gql(mutation, { cookie: signedCookie(oldRefresh) })

		expect(status).toBe(200)
		const refreshed = json.data?.refresh as { accessToken: string }
		track(sessionKey(`access:${refreshed.accessToken}`))
		track(sessionKey(`refresh:${refreshTokenFrom(setCookie)}`))

		// One attempt, over a minute.
		expect(await redisClient.get(attemptKey)).toBe('1')
		const attemptTtl = await redisClient.ttl(attemptKey)
		expect(attemptTtl).toBeGreaterThan(0)
		expect(attemptTtl).toBeLessThanOrEqual(60)

		// One mint, over an hour.
		expect(await redisClient.get(mintKey)).toBe('1')
		expect(await redisClient.ttl(mintKey)).toBeGreaterThan(3540)

		expect(attemptKey).not.toContain(oldRefresh)
		expect(attemptKey).not.toContain(oldRefreshKey.slice((process.env.REDIS_KEY as string).length))
	})
})

describe('GraphQL over HTTP', () => {
	it('serves the query once the introspection code rescues the expired session', async () => {
		const { status, json } = await gql('{ helloRefresh { txt } }', bypassHeaders())

		expect(status).toBe(200)
		expect(json.errors).toBeUndefined()
		expect(json.data).toEqual({ helloRefresh: { txt: 'Hello from helloRefresh' } })
	})

	// Introspection stays open outside production (buildValidationRules returns no rules), and the
	// schema it reports is the one really assembled in createServer — not a copy rebuilt by a test.
	it('exposes the assembled schema through introspection', async () => {
		const { json } = await gql('{ __schema { queryType { name } mutationType { name } } }', bypassHeaders())

		expect(json.errors).toBeUndefined()
		expect(json.data).toEqual({ __schema: { queryType: { name: 'QueriesApi' }, mutationType: { name: 'MutationsApi' } } })
	})

	it('rejects a GET on the GraphQL endpoint (csrfPrevention / method not allowed)', async () => {
		const res = await fetch(`${base}${ENDPOINT}?query=%7B__typename%7D`, { headers: bypassHeaders() })

		expect(res.status).toBeGreaterThanOrEqual(400)
	})
})

describe('non-GraphQL routes', () => {
	it('serves /health once the cookie gate is satisfied', async () => {
		const res = await fetch(`${base}/health`, { headers: bypassHeaders() })

		expect(res.status).toBe(200)
		const json = (await res.json()) as { status: string; timestamp: string }
		expect(json.status).toBe('OK')
	})

	it('falls through to 404 for an unknown path', async () => {
		const res = await fetch(`${base}/nope`, { headers: bypassHeaders() })

		expect(res.status).toBe(404)
	})
})
