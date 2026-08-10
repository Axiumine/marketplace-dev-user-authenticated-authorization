import Keygrip from 'keygrip'
import type { Next } from 'koa'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { IContextUserAuthenticatedAuthorization } from '../src/lib/auth/IContextUserAuthenticatedAuthorization.mts'

const hGetAll = vi.fn()
/*
 * `incr` counts two different things, and which one it counted is the assertion. It is the dual-read
 * counter (E13-S02), touched only when a read misses the hashed key and finds a raw one — and since
 * E14-S08 it is also the counter behind the per-token attempt limiter, which runs on every call.
 * So the steady-state tests pin the key it was called with rather than that it was never called:
 * the limiter must have counted once, the dual-read arm must not have counted at all.
 */
const incr = vi.fn()
// The limiter's other two commands: it arms the window on the first attempt, and reads the TTL back
// only when it finds a counter that has somehow lost one.
const expire = vi.fn()
const ttl = vi.fn()
const tokenInfoUser = vi.fn()

vi.mock('@axiumine/koa-utils/dataSources/Redis', () => ({ redisClient: { hGetAll, incr, expire, ttl } }))
vi.mock('@lib/auth/tokenInfoUser.mjs', () => ({ tokenInfoUser }))

const { authenticatedAuthorizationHandler } = await import('../src/lib/auth/authenticatedAuthorizationHandler.mts')

const keys = new Keygrip(['test-key-1', 'test-key-2'], 'sha512', 'base64')
const REFRESH = '27119032-9043-4a9f-bd4c-9d06fd576290'
// The key that session is written under since E13-S01: the prefix plus the SHA-256 of `refresh:` + it.
const HASHED_KEY = 'test:fd62e117b7af852f29f12e502a239d1b8f31afa959d463de0368d684452cefa5'
// A real 24-hex ObjectId: the handler feeds redData._id straight into new Types.ObjectId().
const OID = '507f1f77bcf86cd799439011'
/*
 * The key the pre-lookup attempt limiter counts under (E14-S08): the prefix, `rl:`, the bucket name, and
 * the SHA-256 of the session digest above — the token hashed a second time. Neither the token nor the key
 * its session lives under is recoverable from it, which is the reason for the second hash. Computed
 * outside this file like every other digest here, so a mutated algorithm cannot agree with itself.
 */
const RATE_LIMIT_KEY = 'test:rl:refresh:token:0b45c6eb3aa4d66a24e7557de17465a30810fc8ec9a90337d016db0e67d2e3c5'

/*
 * The lineage every refresh hash has carried since E14-S01, and which `assertRefreshLineage` refuses a
 * session without: a family the rotations of one login share, the instant that login happened, and the
 * number of days it may go on rotating for. The clock is frozen so `originalLogin` can be a literal —
 * a session stamped `Date.now()` at fixture-build time would age between the fixture and the assertion.
 */
const NOW = 1_754_784_000_000
const LINEAGE = { familyId: '4b1a4a5e-0d3a-4a2f-9a5a-2f0f6a1b8c3d', originalLogin: `${NOW - 1000}`, sessionCapDays: '30' }

// Cookie signed the way Koa emits it: value + `.sig` cookie holding the Keygrip signature.
function signedCookie(token = REFRESH) {
	return `refresh_token=${token}; refresh_token.sig=${keys.sign(`refresh_token=${token}`)}`
}

function makeCtx(header: Record<string, string>) {
	return { request: { header }, state: {} } as unknown as IContextUserAuthenticatedAuthorization
}

/**
 * Redis returns a prototype-less object; the handler spreads it, so mimic that shape.
 *
 * `tier` is passed explicitly on every fixture rather than defaulted silently, because the tier is
 * the one field this service refuses a session over — see the `assertTier` block below.
 *
 * ⚠️ `null` means "omit the field", not `undefined`. A default parameter is skipped only when the
 * argument is `undefined`, so `redisSession(OID, undefined)` would hand back a session tagged `user`
 * — the exact opposite of the case it reads as. That mistake made the pre-tier-field test pass
 * against a fixture that carried the tier.
 */
function redisSession(_id = OID, tier: string | null = 'user') {
	const session: Record<string, string> = { _id, ...LINEAGE }
	if (tier !== null) session.tier = tier

	return Object.assign(Object.create(null), session)
}

describe('authenticatedAuthorizationHandler', () => {
	let next: Next

	beforeEach(() => {
		hGetAll.mockReset()
		incr.mockReset().mockResolvedValue(1)
		expire.mockReset().mockResolvedValue(1)
		// -1 is "key exists, no TTL". The limiter only reads this when repairing a window it lost.
		ttl.mockReset().mockResolvedValue(-1)
		tokenInfoUser.mockReset()
		next = vi.fn().mockResolvedValue('next') as unknown as Next
		// ⚠️ `Date` alone. Faking wholesale replaces the microtask queue the awaited handler runs on.
		vi.useFakeTimers({ toFake: ['Date'] })
		vi.setSystemTime(NOW)
	})

	afterEach(() => vi.useRealTimers())

	it('rejects the request without a cookie', async () => {
		const ctx = makeCtx({})

		await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).rejects.toThrow()
		expect(hGetAll).not.toHaveBeenCalled()
		expect(next).not.toHaveBeenCalled()
	})

	it('rejects a cookie with an invalid signature', async () => {
		const ctx = makeCtx({ cookie: `refresh_token=${REFRESH}; refresh_token.sig=fake-signature` })

		await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).rejects.toThrow()
		expect(hGetAll).not.toHaveBeenCalled()
	})

	it('builds state.user from the Redis session and the user record', async () => {
		hGetAll.mockResolvedValueOnce(redisSession())
		tokenInfoUser.mockResolvedValueOnce({ login: { email: 'customer@marketplace.test' } })

		const ctx = makeCtx({ cookie: signedCookie() })

		await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).resolves.toBe('next')

		// ⚠️ A digest, not the token (E13-S01). The `refresh:` prefix is inside the hashed value, and the
		// literal is computed elsewhere so a mutated algorithm cannot make this test agree with itself.
		expect(hGetAll).toHaveBeenCalledExactlyOnceWith(HASHED_KEY)
		expect(HASHED_KEY).not.toContain(REFRESH)
		// The limiter counted this attempt, and the dual-read arm did not count anything: one `INCR`
		// in total, under the rate-limit key rather than the migration one.
		expect(incr.mock.calls).toEqual([[RATE_LIMIT_KEY]])
		// The id string is turned into an ObjectId before the lookup.
		expect(String(tokenInfoUser.mock.calls[0][0])).toBe(OID)
		expect(ctx.state.user).toEqual({
			_id: OID,
			email: 'customer@marketplace.test',
			tier: 'user',
			refreshToken: `refresh:${REFRESH}`,
			...LINEAGE
		})
		expect(next).toHaveBeenCalledTimes(1)
	})

	// ⚠️ The assertion that matters most here, and the one with no counterpart in the ShopOwner
	// service this was copied from: `toEqual` above already fails on an extra key, but it fails
	// for a shape reason that reads like a typo. This says the thing outright — the customer tier
	// has no onboarding, so no step may ever appear in the session, and a future edit that
	// "restores" the missing `makeOnboardingData` branch is caught by a test that names why.
	it('never puts an onboardingStep in the session — a customer has no onboarding', async () => {
		hGetAll.mockResolvedValueOnce(redisSession())
		tokenInfoUser.mockResolvedValueOnce({
			login: { email: 'customer@marketplace.test', firstLogin: true, onboardingStep: 2, onboardingDone: false }
		})

		const ctx = makeCtx({ cookie: signedCookie() })

		await authenticatedAuthorizationHandler(keys)(ctx, next)

		// Even when the record carries onboarding fields, none of them reaches the session.
		expect(Object.keys(ctx.state.user).sort()).toEqual([
			'_id',
			'email',
			'familyId',
			'originalLogin',
			'refreshToken',
			'sessionCapDays',
			'tier'
		])
	})

	describe('tier assertion', () => {
		// All nine services share one REDIS_KEY prefix, so a well-formed refresh session minted for
		// another tier is findable under this key. Before the tier discriminator existed it was simply
		// accepted. These three cases are that hole, and they must fail closed.
		it.each([
			['shopOwner', 'a ShopOwner refresh session'],
			['admin', 'an Admin refresh session'],
			[null, 'a session minted before the tier field existed']
		])('refuses %s (%s)', async (tier) => {
			hGetAll.mockResolvedValueOnce(redisSession(OID, tier))

			const ctx = makeCtx({ cookie: signedCookie() })

			await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).rejects.toThrow()
			// Refused before the id is looked up: the Mongo lookup is not a substitute for this check,
			// it only fails by accident when the foreign id happens not to exist in `user` too.
			expect(tokenInfoUser).not.toHaveBeenCalled()
			expect(next).not.toHaveBeenCalled()
		})

		it('refuses with 403, not 401 — the caller authenticated, just somewhere else', async () => {
			hGetAll.mockResolvedValueOnce(redisSession(OID, 'shopOwner'))

			await expect(authenticatedAuthorizationHandler(keys)(makeCtx({ cookie: signedCookie() }), next)).rejects.toMatchObject({
				extensions: { http: { status: 403 } }
			})
		})
	})

	it('propagates the rejection when the user is disabled, deleted or gone', async () => {
		hGetAll.mockResolvedValueOnce(redisSession())
		tokenInfoUser.mockRejectedValueOnce(new Error('unauthorized'))

		const ctx = makeCtx({ cookie: signedCookie() })

		await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).rejects.toThrow('unauthorized')
		expect(next).not.toHaveBeenCalled()
	})

	it('rejects when the refresh session no longer exists in Redis', async () => {
		hGetAll.mockResolvedValueOnce({})

		const ctx = makeCtx({ cookie: signedCookie() })

		await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).rejects.toThrow()
		expect(tokenInfoUser).not.toHaveBeenCalled()
		expect(next).not.toHaveBeenCalled()
	})

	it('lets a valid x-introspectioncode through an expired session without touching Mongo', async () => {
		hGetAll.mockResolvedValueOnce({})

		const ctx = makeCtx({ cookie: signedCookie(), 'x-introspectioncode': 'test-introspection-code' })

		await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).resolves.toBe('next')
		expect(tokenInfoUser).not.toHaveBeenCalled()
		expect(ctx.state.user).toBeUndefined()
		expect(next).toHaveBeenCalledTimes(1)
	})

	it('ignores a wrong x-introspectioncode', async () => {
		hGetAll.mockResolvedValueOnce({})

		const ctx = makeCtx({ cookie: signedCookie(), 'x-introspectioncode': 'wrong-code' })

		await expect(authenticatedAuthorizationHandler(keys)(ctx, next)).rejects.toThrow()
	})

	/*
	 * E14-S08. Two limiters guard the refresh endpoint and this is the pre-lookup one, the only one that
	 * ever meters a token resolving to nothing: garbage, expired, tombstoned. A token that names no family
	 * never reaches the per-family limiter inside `refreshSessionTokens` at all, so unless the count
	 * happens here, guessing is free.
	 *
	 * Hence the ordering assertion. "Before the session read" is the whole property — a limiter that ran
	 * after `hGetAll` would still let an attacker walk the keyspace one Redis read at a time.
	 */
	it('meters the attempt against the presented token before it reads the session', async () => {
		hGetAll.mockResolvedValueOnce(redisSession())
		tokenInfoUser.mockResolvedValueOnce({ login: { email: 'customer@marketplace.test' } })

		await expect(authenticatedAuthorizationHandler(keys)(makeCtx({ cookie: signedCookie() }), next)).resolves.toBe('next')

		expect(incr).toHaveBeenCalledExactlyOnceWith(RATE_LIMIT_KEY)
		expect(incr.mock.invocationCallOrder[0]).toBeLessThan(hGetAll.mock.invocationCallOrder[0])
		// A minute, and the window is armed on the first attempt of it.
		expect(expire).toHaveBeenCalledExactlyOnceWith(RATE_LIMIT_KEY, 60)
		// Neither the token nor the key its session lives under survives into the counter's name.
		expect(RATE_LIMIT_KEY).not.toContain(REFRESH)
		expect(RATE_LIMIT_KEY).not.toContain(HASHED_KEY.slice('test:'.length))
	})

	/*
	 * The refusal, and what it must cost: one `INCR` and nothing else. No session read, no Mongo lookup,
	 * no `next()` — a refused attempt that still reads Redis and Mongo is a rate limiter that makes the
	 * flood cheaper for the attacker than for the platform.
	 */
	it('refuses the twenty-first attempt of a minute without reading anything', async () => {
		incr.mockResolvedValueOnce(21)

		await expect(authenticatedAuthorizationHandler(keys)(makeCtx({ cookie: signedCookie() }), next)).rejects.toMatchObject({
			extensions: { http: { status: 429 } }
		})

		expect(hGetAll).not.toHaveBeenCalled()
		expect(tokenInfoUser).not.toHaveBeenCalled()
		expect(next).not.toHaveBeenCalled()
	})

	// The twentieth is still served: twenty attempts are allowed, the twenty-first is not, and `>` versus
	// `>=` inside the limiter differs by exactly this call. Mocked at the boundary for that reason.
	it('serves the twentieth attempt of a minute', async () => {
		incr.mockResolvedValueOnce(20)
		hGetAll.mockResolvedValueOnce(redisSession())
		tokenInfoUser.mockResolvedValueOnce({ login: { email: 'customer@marketplace.test' } })

		await expect(authenticatedAuthorizationHandler(keys)(makeCtx({ cookie: signedCookie() }), next)).resolves.toBe('next')
	})
})
