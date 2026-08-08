import { TCommonHeaders } from '@axiumine/koa-utils/graphQL/schema/context/TCommonHeaders'
import { ICookies } from '@axiumine/koa-utils/lib/ICookies'
import { IRedisDataUserCommon } from '@axiumine/marketplace-common/others/Redis/IRedisDataUserCommon'
import { TAuthorizationSession } from '@axiumine/marketplace-common/others/resolveAuthorizationSession'
import { IncomingHttpHeaders } from 'http'

/**
 * `ctx.state.user` is exactly what `resolveAuthorizationSession` returns — the tier-specific half of
 * the access-token hash, plus the `_id`, the `tier` and the refresh token the session was resolved
 * from. Declaring it as the helper's own return type rather than restating those three fields is what
 * lets the middleware assign the session without a cast, and what stops the two drifting.
 *
 * ⚠️ Still NOT `IRedisDataUserForNode` from marketplace-common, despite the near-identical shape. That
 * one is what a *resource* service holds — `_id` re-hydrated into an ObjectId, no refresh token,
 * because a resource service never sees one. This is the authorization service's: every value still a
 * string, exactly as Redis returned it, plus the refresh token the request arrived with so `refresh`
 * can delete it after minting the replacement.
 */
type IStateApi = {
	user: TAuthorizationSession<IRedisDataUserCommon>
}
export type IContextUserAuthenticatedAuthorization = {
	state: IStateApi
	cookies: ICookies
	request: {
		header?: TCommonHeaders & IncomingHttpHeaders
	}
}
