import { throwUnauthorizedError } from '@axiumine/koa-utils/graphQL/throw/throwUnauthorizedError'
import { User } from '@thedoctorweb_agency/marketplace-common/models/MongoDB/User'
import { IUserModel } from '@thedoctorweb_agency/marketplace-common/models/MongoDBInterfaces/IUserModel'
import { checkUserAuthorizationDisDel } from '@thedoctorweb_agency/marketplace-common/others/checkUserAuthorizationDisDel'
import { Types } from 'mongoose'

/**
 * Re-reads the customer behind a refresh session, so the access token about to be minted carries
 * current data rather than whatever was true at login.
 *
 * ⚠️ **Three fields fewer than `tokenInfoShopOwner`, and the difference is the whole tier.** That one
 * projects `login.firstLogin`, `login.onboardingStep` and `login.onboardingDone` because a shop owner
 * is walked through a multi-step onboarding an operator can interrupt. A customer has none: there is
 * no step to resume, `IRedisDataUserCommon` has no field to put one in, and `firstLogin` is read only
 * to decide whether that onboarding starts from the top.
 *
 * ⚠️ **`emailVerify.valid` is deliberately NOT re-checked here.** `loginUser` on 4028 refuses to mint
 * a session for an unconfirmed address in the first place, so no refresh session can exist for one,
 * and nothing on the platform ever un-confirms an address. `deleted` and `disabled` *can* flip after
 * login, which is why `checkUserAuthorizationDisDel` runs on every refresh rather than at login only:
 * it is what makes disabling an account take effect within one access-token lifetime instead of one
 * refresh-token lifetime.
 */
export async function tokenInfoUser(_id: Types.ObjectId): Promise<IUserModel> {
	const user: IUserModel | null = await User.findById({ _id: _id }, '_id login.email deleted disabled').lean()

	if (user === null) {
		throw throwUnauthorizedError()
	}
	checkUserAuthorizationDisDel(user)
	return user
}
