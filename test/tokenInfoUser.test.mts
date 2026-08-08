import { Types } from 'mongoose'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const lean = vi.fn()
const findById = vi.fn(() => ({ lean }))
const checkUserAuthorizationDisDel = vi.fn()

vi.mock('@axiumine/marketplace-common/models/MongoDB/User', () => ({ User: { findById } }))
vi.mock('@axiumine/marketplace-common/others/checkUserAuthorizationDisDel', () => ({ checkUserAuthorizationDisDel }))

const { tokenInfoUser } = await import('../src/lib/auth/tokenInfoUser.mts')

const _id = new Types.ObjectId('507f1f77bcf86cd799439011')

describe('tokenInfoUser', () => {
	beforeEach(() => {
		lean.mockReset()
		findById.mockClear()
		checkUserAuthorizationDisDel.mockReset()
	})

	it('returns the lean record and runs the disabled/deleted gate on it', async () => {
		const user = { _id, login: { email: 'customer@marketplace.test' }, deleted: false, disabled: false }
		lean.mockResolvedValueOnce(user)

		await expect(tokenInfoUser(_id)).resolves.toBe(user)

		// ⚠️ The projection is the whole tier difference from `tokenInfoShopOwner`, which also asks for
		// login.firstLogin, login.onboardingStep and login.onboardingDone. A customer has no onboarding,
		// so those three must not be fetched: the session shape has nowhere to put them, and reading a
		// field nothing consumes is how the ShopOwner branch would creep back in.
		//
		// It also pins the *absence* of `emailVerify`: `loginUser` on 4028 refuses to mint a session for
		// an unconfirmed address, so no refresh session can exist for one and nothing ever un-confirms
		// an address — re-checking it here would cost a field on every refresh to catch a state that
		// cannot occur. `deleted`/`disabled` are the two that genuinely flip after login, which is why
		// they are projected and the gate below runs on every refresh rather than at login only.
		expect(findById).toHaveBeenCalledExactlyOnceWith({ _id }, '_id login.email deleted disabled')
		expect(checkUserAuthorizationDisDel).toHaveBeenCalledExactlyOnceWith(user)
	})

	it('throws unauthorized when no user matches the id', async () => {
		lean.mockResolvedValueOnce(null)

		await expect(tokenInfoUser(_id)).rejects.toThrow()
		expect(checkUserAuthorizationDisDel).not.toHaveBeenCalled()
	})

	it('propagates the gate rejection for a disabled or deleted user', async () => {
		lean.mockResolvedValueOnce({ _id, login: { email: 'customer@marketplace.test' }, disabled: true })
		checkUserAuthorizationDisDel.mockImplementationOnce(() => {
			throw new Error('disabled')
		})

		await expect(tokenInfoUser(_id)).rejects.toThrow('disabled')
	})
})
