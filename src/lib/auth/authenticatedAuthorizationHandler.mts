import { redisClient } from '@axiumine/koa-utils/dataSources/Redis'
import { IContextRefresh } from '@axiumine/koa-utils/graphQL/schema/context/IContextRefresh'
import { throwRefreshTokenExpiredOrDeleted } from '@axiumine/koa-utils/graphQL/throw/throwRefreshTokenExpiredOrDeleted'
import { verifySignedRefreshToken } from '@axiumine/koa-utils/koa/middleware/authenticatedAuthorizationHandler/verifySignedRefreshToken'
import { IContextUserAuthenticatedAuthorization } from '@lib/auth/IContextUserAuthenticatedAuthorization.mjs'
import { tokenInfoUser } from '@lib/auth/tokenInfoUser.mjs'
import { assertTier } from '@thedoctorweb_agency/marketplace-common/others/assertTier'
import { IRedisDataUser } from '@thedoctorweb_agency/marketplace-common/others/Redis/IRedisDataUser'
import { TIER } from '@thedoctorweb_agency/marketplace-common/others/Tier'
import * as dotenv from 'dotenv'
import Keygrip from 'keygrip'
import { Next } from 'koa'
import { Types } from 'mongoose'

dotenv.config()

/******************
 * receives the refresh token, which carries only the user's _id — not everything the access token holds!
 */

export const authenticatedAuthorizationHandler =
	(keys: Keygrip) => async (ctx: IContextUserAuthenticatedAuthorization, next: Next) => {
		/***************************
		 * The client sends the refresh token as a Koa signed cookie; `verifySignedRefreshToken` checks
		 * the Keygrip signature and hands back the token itself.
		 */

		const refreshTokenRedis = verifySignedRefreshToken(ctx as unknown as IContextRefresh, keys)
		const redSession = await redisClient.hGetAll(`${process.env.REDIS_KEY}${refreshTokenRedis}`)
		if (Object.keys(redSession).length !== 0) {
			const redData = { ...redSession } // For safety, Redis return an object without the default Object.prototype  in its prototype chain.

			// All nine services share one `REDIS_KEY` prefix, so a well-formed refresh session found under
			// this key may have been minted for another tier. Refuse it here, before the _id is looked up
			// in *this* tier's collection — that lookup is not a substitute, it only fails by accident,
			// when the foreign id happens not to exist in `user` too. A session with no `tier` predates
			// the discriminator and is refused as well: fail closed.
			assertTier(redData.tier, TIER.user)

			/***************************
			 * get info for access_token
			 */
			const uId = redData._id
			const uIdObj = new Types.ObjectId(uId) as Types.ObjectId

			const user = await tokenInfoUser(uIdObj)

			// ⚠️ No `makeOnboardingData` and no `onboardingStep`, unlike the ShopOwner service this was
			// copied from. A customer has no onboarding to resume, so there is no step to carry and
			// `IRedisDataUser` has nowhere to put one — the access-token hash is `_id`, `email`, `tier`
			// and nothing else. Do not "restore" the missing branch: it would write a field every
			// consumer of this tier's session would then have to ignore.
			const tokenData: IRedisDataUser = {
				_id: uId,
				email: user.login.email,
				tier: TIER.user
			}

			ctx.state.user = {
				...tokenData,
				refreshToken: refreshTokenRedis
			}
		} else {
			// `ctx.request.header` cannot be nullish here: reaching this branch means
			// verifySignedRefreshToken() (above, inside refreshTokenRedis) already returned
			// without throwing, and it only does that after successfully reading
			// `ctx.request.header?.cookie` as a defined string — which is impossible unless
			// `ctx.request.header` is itself a defined object. The `?.` below can therefore
			// never short-circuit on any reachable input. Equivalent mutant. Pulled into its
			// own statement (rather than inline in the `if` test) so the directive below
			// attaches to this line and not to the enclosing if/else.
			// Stryker disable next-line OptionalChaining: header is provably defined here, see comment above
			const introspectionCode = ctx.request.header?.['x-introspectioncode']
			if (introspectionCode !== `${process.env.INTROSPECTION_CODE}`) {
				throw throwRefreshTokenExpiredOrDeleted()
			} // else return next()
		}

		return next()
	}
