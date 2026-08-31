import { redisClient } from '@axiumine/koa-utils/dataSources/Redis'
import { IContextRefresh } from '@axiumine/koa-utils/graphQL/schema/context/IContextRefresh'
import { verifySignedRefreshToken } from '@axiumine/koa-utils/koa/middleware/authenticatedAuthorizationHandler/verifySignedRefreshToken'
import { IRedisDataUserCommon } from '@axiumine/marketplace-common/others/Redis/IRedisDataUserCommon'
import { guardRefreshAttempt } from '@axiumine/marketplace-common/others/refreshRateLimit'
import { resolveAuthorizationSession } from '@axiumine/marketplace-common/others/resolveAuthorizationSession'
import { TIER } from '@axiumine/marketplace-common/others/Tier'
import { IContextUserAuthenticatedAuthorization } from '@lib/auth/IContextUserAuthenticatedAuthorization.mjs'
import { tokenInfoUser } from '@lib/auth/tokenInfoUser.mjs'
import * as dotenv from 'dotenv'
import Keygrip from 'keygrip'
import { Next } from 'koa'

dotenv.config()

/******************
 * receives the refresh token, which carries only the user's _id — not everything the access token holds!
 *
 * The lookup, the tier assertion, the introspection bypass and the shape of the session are shared with
 * the shop-owner and admin authorization services and live in `resolveAuthorizationSession`. What
 * stays here is the only part that is genuinely this tier's: which collection the `_id` is read from.
 *
 * ⚠️ No `makeOnboardingData` and no `onboardingStep`, unlike the ShopOwner service this was copied
 * from. A customer has no onboarding to resume, so there is no step to carry and `IRedisDataUserCommon`
 * has nowhere to put one — the access-token hash is `_id`, `email`, `tier` and nothing else. Do not
 * "restore" the missing branch: it would write a field every consumer of this tier's session would then
 * have to ignore.
 */

export const authenticatedAuthorizationHandler =
	(keys: Keygrip) => async (ctx: IContextUserAuthenticatedAuthorization, next: Next) => {
		/***************************
		 * The client sends the refresh token as a Koa signed cookie; `verifySignedRefreshToken` checks
		 * the Keygrip signature and hands back the token itself.
		 */
		const refreshToken = verifySignedRefreshToken(ctx as unknown as IContextRefresh, keys)

		// ⚠️ **Before the session read, and that is the whole point**. This is the only limiter that
		// ever meters a token resolving to nothing — garbage, expired, tombstoned — because the per-family one
		// is never reached by a token that names no family. Twenty attempts a minute per token; the signature
		// has already been checked above, so a caller with no valid cookie never gets this far either.
		await guardRefreshAttempt(redisClient, refreshToken)

		const session = await resolveAuthorizationSession<IRedisDataUserCommon>({
			store: redisClient,
			refreshToken,
			tier: TIER.user,
			// `ctx.request.header` cannot be nullish here: verifySignedRefreshToken() (above, inside
			// refreshToken) already returned without throwing, and it only does that after successfully
			// reading `ctx.request.header?.cookie` as a defined string — which is impossible unless
			// `ctx.request.header` is itself a defined object. The `?.` below can therefore never
			// short-circuit on any reachable input. Equivalent mutant.
			// Stryker disable next-line OptionalChaining: header is provably defined here, see comment above
			introspectionCode: ctx.request.header?.['x-introspectioncode'],
			readSessionData: async (_id) => {
				const user = await tokenInfoUser(_id)

				return { email: user.login.email }
			}
		})

		// `null` means the session had expired and the request carried a valid introspection code, so it
		// goes through with no `ctx.state.user` at all — a service-to-service call has no account behind it.
		if (session !== null) ctx.state.user = session

		return next()
	}
