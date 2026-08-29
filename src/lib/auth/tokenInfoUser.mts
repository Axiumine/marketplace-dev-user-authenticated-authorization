import { User } from '@axiumine/marketplace-common/models/MongoDB/User'
import { IUserModel } from '@axiumine/marketplace-common/models/MongoDBInterfaces/IUserModel'
import { findAccountForSession } from '@axiumine/marketplace-common/others/findAccountForSession'
import { Types } from 'mongoose'

/**
 * Re-reads the customer behind a refresh session, so the access token about to be minted carries
 * current data rather than whatever was true at login. The two guards — no document, then
 * disabled/deleted — are shared with the other two tiers and live in `findAccountForSession`; the
 * model and the projection are what this tier contributes.
 *
 * ⚠️ **Three fields fewer than `tokenInfoShopOwner`, and the difference is the whole tier.** That one
 * projects `login.firstLogin`, `login.onboardingStep` and `login.onboardingDone` because a shop owner
 * is walked through a multi-step onboarding an admin can interrupt. A customer has none: there is
 * no step to resume, `IRedisDataUserCommon` has no field to put one in, and `firstLogin` is read only
 * to decide whether that onboarding starts from the top. The projection therefore stays at this call
 * site rather than moving into the shared helper — it is the one part that genuinely differs per tier.
 * Kept inline rather than hoisted to a module constant so it is re-evaluated on every call: a
 * top-level const is evaluated once per process and no test can observe a mutation of it.
 *
 * ⚠️ **`emailVerify.valid` is deliberately NOT re-checked here.** `loginUser` on 4028 refuses to mint
 * a session for an unconfirmed address in the first place, so no refresh session can exist for one,
 * and nothing on the platform ever un-confirms an address. `deleted` and `disabled` *can* flip after
 * login, which is why `checkUserAuthorizationDisDel` — inside `findAccountForSession` — runs on every
 * refresh rather than at login only: it is what makes disabling an account take effect within one
 * access-token lifetime instead of one refresh-token lifetime.
 */
export async function tokenInfoUser(_id: Types.ObjectId): Promise<IUserModel> {
	return findAccountForSession<IUserModel>(User, _id, '_id login.email deleted disabled')
}
