import { TCommonHeaders } from '@axiumine/koa-utils/graphQL/schema/context/TCommonHeaders'
import { ICookies } from '@axiumine/koa-utils/lib/ICookies'
import { IRedisDataUser } from '@thedoctorweb_agency/marketplace-common/others/Redis/IRedisDataUser'
import { IncomingHttpHeaders } from 'http'

/**
 * ⚠️ Local, and NOT `IRedisDataUserForNode` from marketplace-common despite the near-identical name.
 * That one is what a *resource* service holds — `_id` re-hydrated into an ObjectId, no refresh token,
 * because a resource service never sees one. This shape is the authorization service's: every value
 * still a string, exactly as Redis returned it, plus the refresh token the request arrived with so
 * `refresh` can delete it after minting the replacement. The ShopOwner service next door declares its
 * own for the same reason.
 */
interface IRedisDataUserForAuthorization extends IRedisDataUser {
	refreshToken: string
}

type IStateApi = {
	user: IRedisDataUserForAuthorization
}
export type IContextUserAuthenticatedAuthorization = {
	state: IStateApi
	cookies: ICookies
	request: {
		header?: TCommonHeaders & IncomingHttpHeaders
	}
}
