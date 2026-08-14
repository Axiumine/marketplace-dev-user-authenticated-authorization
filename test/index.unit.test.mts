import http from 'node:http'

import type { ApolloServer } from '@apollo/server'
import Keygrip from 'keygrip'
import { Types } from 'mongoose'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

const captureException = vi.fn()
const captureMessage = vi.fn()
const RedisConnect = vi.fn()
const MongoDBConnect = vi.fn()
const disconnectAllDatabases = vi.fn()
const setupFieldEncryption = vi.fn()
const hGetAll = vi.fn()
const hSet = vi.fn()
const expire = vi.fn()
const del = vi.fn()
const hExpire = vi.fn()
const hDel = vi.fn()
// The family set a rotation files its new pair into (E14-S02), and the counter plus its two window
// commands behind both refresh rate limiters (E14-S08). Absent from this stub they are not "unused":
// the middleware calls `incr` on every single request that gets past the cookie signature, so a stub
// missing it answers 500 to the health check.
const sAdd = vi.fn()
const incr = vi.fn()
const ttl = vi.fn()
const findById = vi.fn()
const loadKeygrip = vi.fn()
const watchKeygrip = vi.fn()
const assertHashFieldTTLSupport = vi.fn()

// The connection watchKeygrip subscribes on. Identifiable for the same reason redisClient is: the
// assertion that matters is that it is the DUPLICATE and not the shared client.
const subscriber = { id: 'redis-subscriber', connect: vi.fn() }

// The commands the refresh resolver and the authorization middleware actually call, as one named object
// rather than an inline literal: since ADR-034 start() hands this very client to loadKeygrip, and the
// boot-order test asserts it received THIS one rather than merely something object-shaped. `hExpire` and
// `hDel` joined them with E15-S03 — the rotation arms the successor's field and unfiles the predecessor's,
// so a stub without them answers 500 to every refresh that gets past the signature.
const redisClient = { hGetAll, hSet, expire, del, hExpire, hDel, sAdd, incr, ttl, duplicate: vi.fn(() => subscriber) }

// Two 64-byte keys, newest first, exactly as loadKeygrip answers. Written as bytes: nothing here is a
// real signing key, and the pair has to be distinguishable so the order can be asserted. Distinct from
// the `KEYS` the dispatch suite signs its cookies with — that one is about a running server, this one
// is about what start() reads and hands over.
const KEYGRIP_KEYS = [
	{ id: 'k2', material: Buffer.alloc(64, 17).toString('base64'), createdAt: '2026-08-12T09:14:22.581Z' },
	{ id: 'k1', material: Buffer.alloc(64, 34).toString('base64'), createdAt: '2026-05-01T08:00:00.000Z' }
]

// What a rotation hands back: a key this process has never signed with in front of the ones it has.
const ROTATED_KEYS = [
	{ id: 'k3', material: Buffer.alloc(64, 51).toString('base64'), createdAt: '2026-08-12T11:02:00.000Z' },
	...KEYGRIP_KEYS
]

vi.mock('@sentry/node', () => ({ captureException, captureMessage }))
// The unit project never connects to anything — `start()`'s failure path and the wire tests below both
// run against these stubs.
vi.mock('@axiumine/koa-utils/dataSources/Redis', () => ({ RedisConnect, redisClient }))
vi.mock('@axiumine/koa-utils/dataSources/MongoDB', () => ({ MongoDBConnect }))
// Mocked because the real one opens a ClientEncryption against a live cluster and reads a 96-byte
// key file off disk (ADR-029) — neither exists in the unit project. What start() owes it is that it
// is awaited and that its rejection lands in the same catch as a datasource failure, and both are
// asserted below.
vi.mock('@axiumine/marketplace-common/encryption/setupFieldEncryption', () => ({ setupFieldEncryption }))
vi.mock('@axiumine/marketplace-common/models/MongoDB/User', () => ({ User: { findById } }))
// Mocked for the same reason as setupFieldEncryption above: the real one reads a Redis hash and unwraps
// it under KEYGRIP_KEK (ADR-034), and the unit project connects to nothing. What start() owes it is that
// it is called with this service's own name, before field encryption, and that its refusal is as fatal
// as a datasource failure — all three asserted below.
vi.mock('@axiumine/marketplace-common/others/loadKeygrip', () => ({ loadKeygrip }))
// Mocked so the boot can be asserted without a live subscription: the watch's own behaviour — the
// version comparison, the poll, the holders heartbeat — is unit-tested in marketplace-common against a
// fake store. What start() owes it is the right arguments and the two callbacks, asserted below by
// calling them.
vi.mock('@axiumine/marketplace-common/others/watchKeygrip', () => ({ watchKeygrip }))
// Mocked because the real one issues an `hTTL` against a live server, which the unit project has not got.
// Its own behaviour — which error is translated and which is rethrown untouched — is unit-tested in
// marketplace-common. What start() owes it is the shared client, a position before anything else uses the
// connection, and a refusal as fatal as a datasource failure; all three are asserted below.
vi.mock('@axiumine/marketplace-common/others/assertHashFieldTTLSupport', () => ({ assertHashFieldTTLSupport }))
vi.mock('@lib/db/disconnectAllDatabases.mjs', () => ({ disconnectAllDatabases }))

// Imported dynamically inside beforeAll, not with a top-level `await import`: src/index.mts
// statically imports mutations.mts/queries.mts (for the schema it builds), so a top-level
// import here — even the `await import(...)` form — still runs during Vitest's file-collection
// phase, before any test executes, and its result is the module the entire unit project's
// worker process then keeps reusing. A mutant that changes one of those module-level GraphQL
// literals takes effect during that collection-time evaluation, so Stryker cannot attribute the
// change to any test and reports it Survived. Loading src/index.mts inside beforeAll instead
// makes the whole chain evaluate inside the test run.
//
// The try/catch matters just as much as the dynamic import: a mutant that makes a nested
// GraphQLObjectType constructor throw (mutations.mts/queries.mts, imported transitively) would
// otherwise make this hook itself throw, and Vitest treats a throwing beforeAll as the whole
// file failing to run — every `it` below is reported "skipped", not "failed", and a run with no
// failing (and no passing) test gives Stryker nothing to attribute the kill to, so the mutant is
// reported Survived despite the code visibly crashing. Swallowing the error here leaves every
// binding below undefined instead, so each test that dereferences one fails on its own, as a
// normal per-test failure Stryker can attribute.
let createServer: (typeof import('../src/index.mts'))['createServer']
let ENDPOINT: (typeof import('../src/index.mts'))['ENDPOINT']
let REQUIRED_ENV_VARS: (typeof import('../src/index.mts'))['REQUIRED_ENV_VARS']
let SERVICE_NAME: (typeof import('../src/index.mts'))['SERVICE_NAME']
let checkRequiredEnv: (typeof import('../src/index.mts'))['checkRequiredEnv']
let buildValidationRules: (typeof import('../src/index.mts'))['buildValidationRules']
let healthResponse: (typeof import('../src/index.mts'))['healthResponse']
let logListening: (typeof import('../src/index.mts'))['logListening']
let gracefulShutdown: (typeof import('../src/index.mts'))['gracefulShutdown']
let onUnhandledRejection: (typeof import('../src/index.mts'))['onUnhandledRejection']
let onUncaughtException: (typeof import('../src/index.mts'))['onUncaughtException']
let start: (typeof import('../src/index.mts'))['start']

beforeAll(async () => {
	try {
		;({
			createServer,
			ENDPOINT,
			REQUIRED_ENV_VARS,
			SERVICE_NAME,
			checkRequiredEnv,
			buildValidationRules,
			healthResponse,
			logListening,
			gracefulShutdown,
			onUnhandledRejection,
			onUncaughtException,
			start
		} = await import('../src/index.mts'))
	} catch {
		// Deliberately swallowed — see comment above.
	}
})

describe('checkRequiredEnv', () => {
	/*
	 * ⚠️ The whole list, by value and in order, rather than a length or a `toContain`. This array is a
	 * contract with every environment the service is deployed into, and both ways of breaking it are
	 * silent: a name dropped from here turns a fatal misconfiguration into a service that starts and
	 * fails later, at a request, somewhere that does not name the cause; a name added here and read
	 * nowhere makes every environment carry a value that does nothing. A length check passes a swap and
	 * a `toContain` passes an addition, so neither notices the change. The order is asserted too — the
	 * boot names the *first* missing variable, and that is the one an operator goes looking for. E18-S03.
	 */
	it('requires exactly these 16 variables, in this order', () => {
		expect(REQUIRED_ENV_VARS).toStrictEqual([
			'PORT',
			'KEYGRIP_KEK',
			'REDIS_IS_CLUSTER',
			'REDIS_DB1_HOST',
			'REDIS_DB2_HOST',
			'REDIS_DB3_HOST',
			'REDIS_DB1_PORT',
			'REDIS_DB2_PORT',
			'REDIS_DB3_PORT',
			'REDIS_USERNAME',
			'REDIS_PASSWORD',
			'REDIS_KEY',
			'MONGODB_URI',
			'CSFLE_MASTER_KEY_PATH',
			'CSFLE_KEY_VAULT_NAMESPACE',
			'INTROSPECTION_CODE'
		])
	})

	it('passes when every required variable is set', () => {
		const env = Object.fromEntries(REQUIRED_ENV_VARS.map((k) => [k, 'x']))
		expect(() => checkRequiredEnv(env)).not.toThrow()
	})

	it('throws naming the first missing variable', () => {
		expect(() => checkRequiredEnv({})).toThrow(`Missing required environment variable: ${REQUIRED_ENV_VARS[0]}`)
	})

	/*
	 * Both entries named as literals, because the two tests above cannot see WHICH names the list
	 * carries: the first builds its passing environment out of the list itself, so a corrupted entry
	 * is satisfied by the very stub the corruption produced, and the second only ever reads
	 * REQUIRED_ENV_VARS[0].
	 *
	 * MONGODB_URI — start() calls MongoDBConnect(), so without the guard a missing URI surfaces as a
	 * driver error from inside the try, reported to Sentry and exited 1, instead of one line before
	 * anything connects.
	 * INTROSPECTION_CODE — the service-to-service bypass compares the header against
	 * `${process.env.INTROSPECTION_CODE}`, which stringifies an unset value to 'undefined' and admits
	 * any caller sending that literal string.
	 */
	it('requires MONGODB_URI and INTROSPECTION_CODE by name', () => {
		expect(REQUIRED_ENV_VARS).toContain('MONGODB_URI')
		expect(REQUIRED_ENV_VARS).toContain('INTROSPECTION_CODE')
	})

	/*
	 * ⚠️ ADR-034, and the same literal-name argument as the test above. The KEK is the only cookie-key
	 * material this service still reads from its environment; the signing keys themselves come from
	 * Redis. The two old names are asserted GONE, not merely absent from the code: leaving them in the
	 * boot contract would keep a service refusing to start over variables nothing reads any more.
	 */
	it('requires the KEK by name, and no longer the signing keys themselves', () => {
		expect(REQUIRED_ENV_VARS).toContain('KEYGRIP_KEK')
		expect(REQUIRED_ENV_VARS).not.toContain('KEYGRIP_KEY_1')
		expect(REQUIRED_ENV_VARS).not.toContain('KEYGRIP_KEY_2')
	})
})

// The name this service writes into the keygrip holders table. Asserted as a literal because the
// table is how an operator tells five services apart, and a row nobody recognises is worse than no row.
describe('SERVICE_NAME', () => {
	it('is the repository name', () => {
		expect(SERVICE_NAME).toBe('marketplace-dev-user-authenticated-authorization')
	})
})

describe('buildValidationRules', () => {
	it('is empty outside production', () => {
		expect(buildValidationRules({ NODE_ENV: 'test' })).toEqual([])
	})

	it('caps depth and blocks introspection in production', () => {
		expect(buildValidationRules({ NODE_ENV: 'production' })).toHaveLength(2)
	})
})

describe('healthResponse', () => {
	it('reports OK with a round-trippable ISO timestamp', () => {
		const res = healthResponse()
		expect(res.status).toBe('OK')
		expect(res.timestamp).toBe(new Date(res.timestamp).toISOString())
	})
})

describe('logListening', () => {
	let info: ReturnType<typeof vi.spyOn>

	beforeEach(() => {
		captureMessage.mockReset()
		info = vi.spyOn(console, 'info').mockImplementation(() => undefined)
	})
	afterEach(() => {
		info.mockRestore()
		vi.unstubAllEnvs()
	})

	// The real call site (start(), see below) invokes logListening() with NO arguments at all,
	// falling back to process.env — it never passes an explicit env object. A test that only
	// exercises the explicit-argument form can pass while the production path prints "undefined"
	// for a value process.env genuinely lacks (this happened: HOSTNAME was removed from the env
	// template and REQUIRED_ENV_VARS, but logListening used to still read env.HOSTNAME). These two
	// tests stub process.env and call logListening() with zero arguments, matching start() exactly.
	it('with no arguments, logs the exact banner built from process.env outside production', () => {
		vi.stubEnv('NODE_ENV', 'test')
		vi.stubEnv('PORT', '4029')

		logListening()

		expect(info).toHaveBeenCalledExactlyOnceWith(`Serving http://*:4029${ENDPOINT} for test.`)
		expect(captureMessage).not.toHaveBeenCalled()
	})

	it('with no arguments, also mirrors the exact banner to Sentry in production', () => {
		vi.stubEnv('NODE_ENV', 'production')
		vi.stubEnv('PORT', '80')

		logListening()

		const expected = `Serving http://*:80${ENDPOINT} for production.`
		expect(captureMessage).toHaveBeenCalledExactlyOnceWith(expected, 'info')
		expect(info).toHaveBeenCalledExactlyOnceWith(expected)
	})

	it('logs to the console only, outside production', () => {
		logListening({ NODE_ENV: 'test', PORT: '4029' })
		expect(info).toHaveBeenCalledExactlyOnceWith(`Serving http://*:4029${ENDPOINT} for test.`)
		expect(captureMessage).not.toHaveBeenCalled()
	})

	it('also mirrors the banner to Sentry in production, naming no single host', () => {
		logListening({ NODE_ENV: 'production', PORT: '80' })
		// The `*` stands in for the address: the server binds every interface, so there is no
		// single host to print.
		const expected = `Serving http://*:80${ENDPOINT} for production.`
		expect(captureMessage).toHaveBeenCalledExactlyOnceWith(expected, 'info')
		expect(info).toHaveBeenCalledExactlyOnceWith(expected)
	})
})

describe('gracefulShutdown', () => {
	beforeEach(() => {
		captureMessage.mockReset()
		disconnectAllDatabases.mockReset()
	})

	it('drains Apollo, closes the server and disconnects with code 0', async () => {
		const apolloServer = { stop: vi.fn().mockResolvedValue(undefined) }
		const httpServer = { close: vi.fn((cb: () => void) => cb()) }

		await gracefulShutdown('SIGTERM', apolloServer as never, httpServer as never)

		expect(captureMessage).toHaveBeenCalledWith('SIGTERM received, shutting down gracefully...')
		expect(apolloServer.stop).toHaveBeenCalledTimes(1)
		expect(disconnectAllDatabases).toHaveBeenCalledWith(0)
	})
})

describe('process handlers', () => {
	let exit: ReturnType<typeof vi.spyOn>

	beforeEach(() => {
		captureException.mockReset()
		exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never)
	})
	afterEach(() => exit.mockRestore())

	it('onUnhandledRejection reports the reason and exits 1', () => {
		const reason = new Error('boom')
		onUnhandledRejection(reason)
		expect(captureException).toHaveBeenCalledWith(reason)
		expect(exit).toHaveBeenCalledWith(1)
	})

	it('onUncaughtException reports the error and exits 1', () => {
		const error = new Error('kaboom')
		onUncaughtException(error)
		expect(captureException).toHaveBeenCalledWith(error)
		expect(exit).toHaveBeenCalledWith(1)
	})
})

describe('start (failure path)', () => {
	let errorLog: ReturnType<typeof vi.spyOn>

	beforeEach(() => {
		captureException.mockReset()
		disconnectAllDatabases.mockReset()
		RedisConnect.mockReset()
		MongoDBConnect.mockReset().mockResolvedValue(undefined)
		setupFieldEncryption.mockReset().mockResolvedValue(undefined)
		assertHashFieldTTLSupport.mockReset().mockResolvedValue(undefined)
		loadKeygrip.mockReset().mockResolvedValue({ version: 1, fp: 'c77808de4139', keys: KEYGRIP_KEYS })
		watchKeygrip.mockReset().mockResolvedValue(undefined)
		subscriber.connect.mockReset().mockResolvedValue(undefined)
		redisClient.duplicate.mockClear()
		for (const k of REQUIRED_ENV_VARS) vi.stubEnv(k, 'x')
		errorLog = vi.spyOn(console, 'error').mockImplementation(() => undefined)
	})
	afterEach(() => {
		errorLog.mockRestore()
		vi.unstubAllEnvs()
	})

	it('reports to Sentry and disconnects with code 1 when Redis fails to connect', async () => {
		const error = new Error('redis boom')
		RedisConnect.mockRejectedValueOnce(error)

		await start()

		expect(RedisConnect).toHaveBeenCalledTimes(1)
		expect(captureException).toHaveBeenCalledWith(error)
		expect(disconnectAllDatabases).toHaveBeenCalledWith(1)
	})

	// Both datasources are opened by the same Promise.all, so MongoDB's rejection has to be
	// covered separately — Redis resolving is not enough to prove the catch handles either side.
	it('reports to Sentry and disconnects with code 1 when MongoDB fails to connect', async () => {
		const error = new Error('mongo boom')
		RedisConnect.mockResolvedValueOnce(undefined)
		MongoDBConnect.mockRejectedValueOnce(error)

		await start()

		expect(captureException).toHaveBeenCalledWith(error)
		expect(disconnectAllDatabases).toHaveBeenCalledWith(1)
	})

	/*
	 * ⚠️ The refusal this whole design exists for. A service that could not unwrap the record and started
	 * anyway would sign cookies with keys no sibling can verify, and the symptom — some requests
	 * authenticate and some do not, depending on which service the edge picked — is one this platform has
	 * already paid for twice. Fatal, on the same path as a datasource failure.
	 */
	it('reports to Sentry and disconnects with code 1 when the keygrip record cannot be read', async () => {
		const error = new Error('KEYGRIP_KEK_MISMATCH: this service cannot unwrap keygrip record version 3 (c77808de4139).')
		loadKeygrip.mockRejectedValueOnce(error)

		await start()

		expect(errorLog).toHaveBeenCalledExactlyOnceWith('error', error)
		expect(captureException).toHaveBeenCalledWith(error)
		expect(disconnectAllDatabases).toHaveBeenCalledWith(1)
	})

	/*
	 * ⚠️ Booting deaf is not an option either. A process that could read the record once but cannot hold a
	 * subscription would keep signing with the key it started with, through every rotation, for as long as
	 * it runs — the exact drift the record replaced five environment files to prevent, only slower to
	 * notice. Fatal, and fatal *before* listen(), so no cookie is ever signed by a deaf process.
	 */
	it('reports to Sentry and disconnects with code 1 when the subscriber connection cannot be opened', async () => {
		const error = new Error('subscriber boom')
		subscriber.connect.mockRejectedValueOnce(error)

		await start()

		expect(watchKeygrip).not.toHaveBeenCalled()
		expect(errorLog).toHaveBeenCalledExactlyOnceWith('error', error)
		expect(captureException).toHaveBeenCalledWith(error)
		expect(disconnectAllDatabases).toHaveBeenCalledWith(1)
	})

	/*
	 * ⚠️ **A Redis without hash-field TTLs is a Redis this service cannot refresh anybody on** (E15-S03).
	 * Every rotation it serves files the successor session under its account and arms an `HEXPIRE` on that
	 * field, and Redis answers an unknown command at first use rather than at startup — so without this
	 * refusal the process comes up green, verifies tokens all morning, and fails the first refresh by
	 * logging the customer out of a session that was still valid.
	 */
	it('reports to Sentry and disconnects with code 1 when the server has no hash-field TTLs', async () => {
		const error = new Error(
			'Redis is older than 7.4.0: hash-field TTLs (HEXPIRE/HTTL) are missing, and the session index cannot prune itself without them. See docker-DBs/README.md §Redis.'
		)
		assertHashFieldTTLSupport.mockRejectedValueOnce(error)

		await start()

		// Refused before the keys are even read: nothing else touches the connection first, so the log
		// carries the version problem and not whatever the next step made of it.
		expect(loadKeygrip).not.toHaveBeenCalled()
		expect(errorLog).toHaveBeenCalledExactlyOnceWith('error', error)
		expect(captureException).toHaveBeenCalledWith(error)
		expect(disconnectAllDatabases).toHaveBeenCalledWith(1)
	})

	// A service that came up with field encryption broken would answer queries with ciphertext and
	// write plaintext beside it, so this failure has to be as fatal as a datasource failure.
	it('reports to Sentry and disconnects with code 1 when field encryption cannot start', async () => {
		const error = new Error('CSFLE_MASTER_KEY_PATH is not set — field encryption cannot start without it')
		setupFieldEncryption.mockRejectedValueOnce(error)

		await start()

		expect(setupFieldEncryption).toHaveBeenCalledTimes(1)
		expect(captureException).toHaveBeenCalledWith(error)
		expect(disconnectAllDatabases).toHaveBeenCalledWith(1)
	})
})

describe('start (success path)', () => {
	let listenSpy: ReturnType<typeof vi.spyOn>

	beforeEach(() => {
		captureException.mockReset()
		RedisConnect.mockReset().mockResolvedValue(undefined)
		MongoDBConnect.mockReset().mockResolvedValue(undefined)
		setupFieldEncryption.mockReset().mockResolvedValue(undefined)
		assertHashFieldTTLSupport.mockReset().mockResolvedValue(undefined)
		loadKeygrip.mockReset().mockResolvedValue({ version: 1, fp: 'c77808de4139', keys: KEYGRIP_KEYS })
		watchKeygrip.mockReset().mockResolvedValue(undefined)
		subscriber.connect.mockReset().mockResolvedValue(undefined)
		redisClient.duplicate.mockClear()
		disconnectAllDatabases.mockClear()
		for (const k of REQUIRED_ENV_VARS) vi.stubEnv(k, 'x')
		// listen() itself is stubbed out below, so PORT can stay the same placeholder as every
		// other required var — no socket is ever really opened by this test.
		listenSpy = vi.spyOn(http.Server.prototype, 'listen').mockImplementation(function (this: http.Server, ...args: unknown[]) {
			const callback = args.find((arg): arg is () => void => typeof arg === 'function')
			callback?.()

			return this
		})
	})
	afterEach(() => {
		listenSpy.mockRestore()
		vi.unstubAllEnvs()
	})

	it('passes only { port }, never a host, to listen — binding every interface on purpose', async () => {
		const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)

		const server = await start()

		// The whole point of the fix this asserts: no `host`/`hostname` key travels into listen()
		// at all. Node silently ignores an unrecognised option, so a regression here would not
		// throw — this exact-shape check is the only thing that would catch it, and it is also
		// what kills mutants on this call (a mutated options object would fail the match).
		expect(listenSpy).toHaveBeenCalledExactlyOnceWith({ port: process.env.PORT }, expect.any(Function))
		// Once, with no arguments: it reads its configuration from the environment, and a caller that
		// passed it anything would be building a second source of truth for the master key path.
		expect(setupFieldEncryption).toHaveBeenCalledExactlyOnceWith()

		await server?.apolloServer.stop()
		info.mockRestore()
	})

	/*
	 * The probe runs on the shared client — the one every session read and every rotation uses — and it runs
	 * before the keygrip is unwrapped, so a version refusal is the first thing in the log rather than the
	 * third. Handing it a duplicate would prove a connection this service never writes sessions on.
	 */
	it('probes the server for hash-field TTLs on the shared client, before anything else uses it', async () => {
		const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)

		const server = await start()

		expect(assertHashFieldTTLSupport).toHaveBeenCalledExactlyOnceWith(redisClient)
		expect(assertHashFieldTTLSupport.mock.invocationCallOrder[0]).toBeLessThan(loadKeygrip.mock.invocationCallOrder[0])

		await server?.apolloServer.stop()
		info.mockRestore()
	})

	/*
	 * ⚠️ Two things at once, and both are ordering. The keys are read with THIS service's own name — the
	 * holders table is worthless if five services write the same label — and they are read BEFORE field
	 * encryption, because the connect that answers them is the one that just resolved and because a boot
	 * that is going to be refused should be refused before it opens a ClientEncryption.
	 */
	it('reads the signing keys under its own name, right after the connect and before field encryption', async () => {
		const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)

		const server = await start()

		expect(loadKeygrip).toHaveBeenCalledExactlyOnceWith(redisClient, SERVICE_NAME)
		expect(loadKeygrip.mock.invocationCallOrder[0]).toBeLessThan(setupFieldEncryption.mock.invocationCallOrder[0])

		await server?.apolloServer.stop()
		info.mockRestore()
	})

	/*
	 * ⚠️ Armed on a connection of its own, with the version the boot read, before the socket opens. Each
	 * of those three is a way this can be wired wrongly and still look right: the shared client would
	 * break every session read the moment a message arrives, a hard-coded starting version would make the
	 * first rotation invisible or replay one that already landed, and arming it after `listen()` leaves a
	 * window where this process signs cookies it will never learn to stop signing.
	 */
	it('watches the record on a duplicated connection, from the version it booted with, before it listens', async () => {
		const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)

		const server = await start()

		expect(redisClient.duplicate).toHaveBeenCalledExactlyOnceWith()
		expect(subscriber.connect).toHaveBeenCalledExactlyOnceWith()
		expect(watchKeygrip).toHaveBeenCalledExactlyOnceWith({
			store: redisClient,
			subscriber,
			serviceName: SERVICE_NAME,
			version: 1,
			fp: 'c77808de4139',
			onKeys: expect.any(Function),
			onError: expect.any(Function)
		})
		expect(watchKeygrip.mock.invocationCallOrder[0]).toBeLessThan(listenSpy.mock.invocationCallOrder[0])

		await server?.apolloServer.stop()
		info.mockRestore()
	})

	/*
	 * The rotation, as this process experiences it: no restart, no reconnect, a new array in `app.keys`.
	 * Asserted through a signature because `Keygrip` keeps its keys private — and a signature is also what
	 * proves the *material* reached it in the right order, rather than the ids or the whole objects.
	 */
	it('rebuilds the signing keys in place when the watch reports a new record', async () => {
		const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)

		const server = await start()
		const { onKeys } = watchKeygrip.mock.calls[0][0] as {
			onKeys: (record: { version: number; fp: string; keys: typeof KEYGRIP_KEYS }) => void
		}
		// `app.keys` is typed `Keygrip | string[]` by Koa; this service only ever assigns the first.
		const signing = () => server?.app.keys as Keygrip

		expect(signing().sign('session-cookie')).toBe(new Keygrip([KEYGRIP_KEYS[0].material], 'sha512').sign('session-cookie'))

		onKeys({ version: 2, fp: '0b1d9f2c4a77', keys: ROTATED_KEYS })

		// Signs with the key that did not exist a line ago...
		expect(signing().sign('session-cookie')).toBe(new Keygrip([ROTATED_KEYS[0].material], 'sha512').sign('session-cookie'))
		// ...and still verifies the one it was signing with, which is what keeps every issued cookie valid
		// across the rotation instead of logging the whole platform out.
		expect(signing().index('session-cookie', new Keygrip([KEYGRIP_KEYS[0].material], 'sha512').sign('session-cookie'))).toBe(1)

		await server?.apolloServer.stop()
		info.mockRestore()
	})

	/*
	 * ⚠️ Reported and dropped, never thrown. `onError` runs on a socket callback and on a timer, where a
	 * throw is an unhandled rejection that kills a process which is serving perfectly well on keys every
	 * sibling still verifies. Losing the ability to re-read is a Sentry event, not an outage.
	 */
	it('reports a failed re-read to Sentry without taking the service down', async () => {
		const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)

		const server = await start()
		const { onError } = watchKeygrip.mock.calls[0][0] as { onError: (error: unknown) => void }
		const error = new Error('KEYGRIP_KEK_MISMATCH: this service cannot unwrap keygrip record version 4 (0b1d9f2c4a77).')

		captureException.mockClear()
		expect(() => onError(error)).not.toThrow()

		expect(captureException).toHaveBeenCalledExactlyOnceWith(error)
		expect(disconnectAllDatabases).not.toHaveBeenCalled()

		await server?.apolloServer.stop()
		info.mockRestore()
	})
})

// ⚠️ The three arms of the dispatch middleware are driven here, over a real socket, because this
// repo's **integration project cannot run**: all seven MONGO_TEST_* keys are missing from the
// machine's environment file, so `assertTestMongoEnv` aborts `globalSetup` before a single test is
// collected. These tests are not a replacement for that suite — Mongo and Redis are stubbed — but
// they are what makes the coverage number honest without a database, and they exercise the one thing
// no unit test of a resolver can: that the middleware order in `createServer()` is what it claims.
describe('request dispatch', () => {
	let httpServer: http.Server
	let apolloServer: ApolloServer
	let origin: string

	const userId = new Types.ObjectId('507f1f77bcf86cd799439011')
	const REFRESH = '27119032-9043-4a9f-bd4c-9d06fd576290'
	const INTROSPECTION = { 'x-introspectioncode': 'test-introspection-code' }
	// Two keys, because Keygrip rotates: the first signs, any of them verifies.
	const KEYS = ['a'.repeat(64), 'b'.repeat(64)]

	/** The cookie pair `verifySignedRefreshToken` reads — the token and its Keygrip SHA-512 signature. */
	function signedCookie(token = REFRESH) {
		const signature = new Keygrip(KEYS, 'sha512').sign(`refresh_token=${token}`)

		return { cookie: `refresh_token=${token}; refresh_token.sig=${signature}` }
	}

	/*
	 * The lineage a real login stamps on every refresh hash (E14-S01) rides along on every fixture, because
	 * `assertRefreshLineage` refuses a session without it — a fixture missing it is refused at the guard
	 * and proves nothing about the dispatch each test is really about.
	 */
	function session(tier: string) {
		return Object.assign(Object.create(null), {
			_id: String(userId),
			tier,
			familyId: '4b1a4a5e-0d3a-4a2f-9a5a-2f0f6a1b8c3d',
			originalLogin: `${Date.now()}`,
			sessionCapDays: '30'
		})
	}

	beforeAll(async () => {
		// Since ADR-034 the keys are an argument rather than two environment variables, so the pair this
		// suite signs with is simply handed over — same order, first one signs. Nothing to stub, and
		// nothing a later unstub could take away from the running server.
		const server = await createServer(
			KEYS.map((material, index) => ({ id: `k${index}`, material, createdAt: '2026-08-12T00:00:00.000Z' }))
		)
		httpServer = server.httpServer
		apolloServer = server.apolloServer

		await new Promise<void>((resolve) => httpServer.listen({ port: 0 }, () => resolve()))
		origin = `http://127.0.0.1:${(httpServer.address() as { port: number }).port}`
	})

	afterAll(async () => {
		await apolloServer.stop()
		await new Promise<void>((resolve) => httpServer.close(() => resolve()))
		vi.unstubAllEnvs()
	})

	beforeEach(() => {
		hGetAll.mockReset()
		findById.mockReset()
		hSet.mockReset().mockResolvedValue(undefined)
		expire.mockReset().mockResolvedValue(undefined)
		del.mockReset().mockResolvedValue(undefined)
		hExpire.mockReset().mockResolvedValue([1])
		hDel.mockReset().mockResolvedValue(1)
		sAdd.mockReset().mockResolvedValue(1)
		// 1 is the first attempt of a window, which every test here is; -1 is "no TTL", read only when
		// the limiter repairs a window it lost.
		incr.mockReset().mockResolvedValue(1)
		ttl.mockReset().mockResolvedValue(-1)
		captureException.mockReset()
	})

	// ⚠️ **The introspection code alone is not a credential on this service**, unlike the resource
	// ones. It is consulted only *after* `verifySignedRefreshToken` has already returned a token, so
	// a service-to-service caller still needs a properly signed cookie; what the code then buys it is
	// permission to proceed with no session behind that cookie. Hence the pairing in every test
	// below, and the explicit 412 test further down.
	function serviceCall() {
		hGetAll.mockResolvedValueOnce({})

		return { ...signedCookie(), ...INTROSPECTION }
	}

	it('answers the health check on /health', async () => {
		const res = await fetch(`${origin}/health`, { headers: serviceCall() })

		expect(res.status).toBe(200)
		await expect(res.json()).resolves.toMatchObject({ status: 'OK' })
	})

	// The else arm: anything that is neither the GraphQL endpoint nor /health falls through to a Koa
	// 404. Nothing else is mounted — this service has no REST surface at all, and the only three REST
	// endpoints on the platform live on the public resource service.
	it('answers 404 on any other path', async () => {
		const res = await fetch(`${origin}/anything-else`, { headers: serviceCall() })

		expect(res.status).toBe(404)
	})

	// Auth runs before dispatch, so even the health check needs a credential. 412 rather than 401:
	// the request carried no cookie header at all, which is a precondition failure and not a rejected
	// identity.
	it('refuses the health check with no cookie at all', async () => {
		const res = await fetch(`${origin}/health`)

		expect(res.status).toBe(412)
	})

	// The bypass is narrower here than the header's name suggests, and this pins it: an
	// x-introspectioncode with no cookie is still 412. The code stands in for a *session*, never for
	// the signature — so a leaked code alone cannot be replayed against this service.
	it('does not let the introspection code stand in for a missing cookie', async () => {
		const res = await fetch(`${origin}/health`, { headers: INTROSPECTION })

		expect(res.status).toBe(412)
		expect(hGetAll).not.toHaveBeenCalled()
	})

	// A cookie whose signature does not verify under either key. 401, and note it never reaches
	// Redis — a forged cookie is refused by the Keygrip check, not by a missing session.
	it('refuses a refresh cookie whose signature does not verify', async () => {
		const res = await fetch(`${origin}/health`, { headers: { cookie: `refresh_token=${REFRESH}; refresh_token.sig=forged` } })

		expect(res.status).toBe(401)
		expect(hGetAll).not.toHaveBeenCalled()
	})

	// The Apollo arm end to end: cookie verified, session read, tier asserted, customer re-read,
	// both hashes written, the old refresh key deleted and a new signed cookie set on the way out.
	it('mints a new token pair for a customer refresh session', async () => {
		hGetAll.mockResolvedValueOnce(session('user'))
		findById.mockReturnValueOnce({ lean: async () => ({ _id: userId, login: { email: 'cliente@marketplace.test' } }) })

		const res = await fetch(`${origin}${ENDPOINT}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json', ...signedCookie() },
			body: JSON.stringify({ query: 'mutation { refresh { status accessToken } }' })
		})

		expect(res.status).toBe(200)
		const body = (await res.json()) as { data: { refresh: { status: boolean; accessToken: string } } }
		expect(body.data.refresh.status).toBe(true)
		expect(body.data.refresh.accessToken).not.toBe('')

		// The refresh token this call was made with is deleted, so a stolen copy is worthless the
		// moment the legitimate client uses it — rotation, not just re-issue.
		//
		// ⚠️ One shape goes, and one is enough since E13-S10: the hashed key is the only name a session has.
		// The second del this rotation used to issue named the pre-cutover raw key, and it left with the
		// fallback that could read it — a round trip per refresh against a key nothing can write.
		expect(del).toHaveBeenCalledExactlyOnceWith('test:fd62e117b7af852f29f12e502a239d1b8f31afa959d463de0368d684452cefa5')
		expect(res.headers.getSetCookie().join(' ')).toContain('refresh_token')
	})

	// ⚠️ The cross-tier refusal over the wire. All nine services read Redis under one REDIS_KEY
	// prefix, so a ShopOwner refresh session is *findable* here; before the tier discriminator
	// existed this request was served, and the `_id` lookup in `user` was no substitute — it only
	// fails by accident, when the foreign id happens not to exist in `user` too.
	it('refuses a ShopOwner refresh session with 403', async () => {
		hGetAll.mockResolvedValueOnce(session('shopOwner'))

		const res = await fetch(`${origin}${ENDPOINT}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json', ...signedCookie() },
			body: JSON.stringify({ query: 'mutation { refresh { status } }' })
		})

		expect(res.status).toBe(403)
		expect(findById).not.toHaveBeenCalled()
	})

	// csrfPrevention is on in every service here, and it rejects a GET carrying none of Apollo's
	// preflight-forcing headers. This is why the frontends set `preferGetMethod: false` on urql: at
	// the default, every query short enough to fit in a URL fails while mutations work.
	it('refuses a bare GET on the endpoint', async () => {
		const res = await fetch(`${origin}${ENDPOINT}?query=%7BhelloRefresh%7Btxt%7D%7D`, { headers: serviceCall() })

		expect(res.status).toBe(400)
	})
})

// ⚠️ **`app.proxy` off is load-bearing, not an unset default nobody thought about.** With it off,
// `ctx.ip` is the socket address — nginx's own — so no client address is reachable in this process
// at all, which is the design: the per-caller rate limit is the edge's (`conf.d/20-rate-limit.conf`
// keys its zones on `$binary_remote_addr` after `real_ip_header CF-Connecting-IP`), and nothing here
// can write a visitor's address to Redis, to a log line or to Sentry. Turning it on would silently
// start trusting `X-Forwarded-For` and start producing real addresses everywhere `ctx.ip` is read.
// A comment cannot prevent that; this test can, and it is the reason the setting is never assigned.
describe('app.proxy', () => {
	it('is off on the constructed Koa app', async () => {
		for (const k of REQUIRED_ENV_VARS) vi.stubEnv(k, 'x')

		const { app, apolloServer } = await createServer(KEYGRIP_KEYS)

		expect(app.proxy).toBeFalsy()

		await apolloServer.stop()
		vi.unstubAllEnvs()
	})
})

/*
 * ⚠️ What `Keygrip` is built from, and in which order (ADR-034). Signatures are compared rather than
 * the array being read back, because `Keygrip` keeps its keys private — and comparing signatures is
 * also what proves the algorithm is still sha512 and that the *material* is what reaches it, not the
 * key ids or the whole objects.
 */
describe('the signing keys', () => {
	it('signs with the first key, verifies with the older one, and stays sha512', async () => {
		for (const k of REQUIRED_ENV_VARS) vi.stubEnv(k, 'x')

		const { apolloServer, keys } = await createServer(KEYGRIP_KEYS)
		const newest = new Keygrip([KEYGRIP_KEYS[0].material], 'sha512')
		const oldest = new Keygrip([KEYGRIP_KEYS[1].material], 'sha512')

		// Index 0 is the key that signs — the array order decides which, and reversing it would make
		// this service sign with a key its siblings are only verifying with.
		expect(keys.sign('session-cookie')).toBe(newest.sign('session-cookie'))
		expect(keys.sign('session-cookie')).not.toBe(oldest.sign('session-cookie'))

		// And the older key still verifies, at its own index: this is what carries already-issued
		// cookies across a rotation instead of logging everyone out.
		expect(keys.index('session-cookie', oldest.sign('session-cookie'))).toBe(1)

		await apolloServer.stop()
		vi.unstubAllEnvs()
	})
})

/*
 * ⚠️ The boot itself, not just `checkRequiredEnv`. The check runs OUTSIDE `start()`'s try, so a missing
 * variable has to travel out of `start()` to the caller instead of being swallowed into the
 * disconnect-and-exit that handles a datasource failure — and it must get there before anything has
 * connected, because a datasource handle left half-open by a boot nobody completed is a connection
 * the pool goes on holding. E18-S03.
 */
describe('start (missing environment)', () => {
	afterEach(() => {
		vi.unstubAllEnvs()
	})

	it('rejects — with no datasource touched — when a required variable is missing', async () => {
		for (const k of REQUIRED_ENV_VARS) vi.stubEnv(k, 'x')
		vi.stubEnv('REDIS_KEY', '')
		RedisConnect.mockClear()
		disconnectAllDatabases.mockClear()

		await expect(start()).rejects.toThrow('Missing required environment variable: REDIS_KEY')
		expect(RedisConnect).not.toHaveBeenCalled()
		expect(disconnectAllDatabases).not.toHaveBeenCalled()
	})
})
