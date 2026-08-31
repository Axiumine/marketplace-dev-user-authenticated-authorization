import { readFile } from 'node:fs/promises'

import { ESLint } from 'eslint'
import { describe, expect, it } from 'vitest'

/*
 * The `no-restricted-syntax` block in `eslint.config.js`, proved one selector at a time.
 *
 * A rule nobody exercises is a comment. Each fixture below is the *exact* shape the rule exists to
 * refuse — including the assignment form the audit actually found, which a `Property`-only selector
 * would have let through — and the last one is the compliant shape, which must stay silent.
 *
 * The fixtures are `.mts.fixture` rather than `.mts` on purpose: a real `.mts` under `test/` would be
 * linted by `yarn lint` and report the very findings it is here to contain, and adding it to `ignores`
 * would then hide it from this suite too. They are read as text and linted through `lintText` at a
 * `test/`-shaped path, which is the config this block applies to along with every other file.
 */

const FIXTURES = new URL('./fixtures/restrictedSyntax/', import.meta.url)

const TLS_MESSAGE = 'certificate verification stays on.'
const PII_MESSAGE = 'the blanket Sentry PII flag is absent by decision, not set to false.'
const BODY_MESSAGE = 'the request body is never captured.'
const HOOKS_MESSAGE = '`beforeSend` and `beforeSendTransaction` are wired together or not at all.'
const KEYGRIP_MESSAGE = 'KEYGRIP_KEY_1/KEYGRIP_KEY_2 are gone since ADR-034.'
const DISABLED_MESSAGE = 'ADR-044: `disabled`, `disabledBy` and `disabledReason` are the Admin tier'

/*
 * The path matters as much as the code here: the keygrip ban is scoped to `src/**`, so the same
 * fixture text is a finding at one path and silent at the other. Both are linted here — a fixture that
 * only ever ran at a test path could not tell a correctly scoped rule from one that stopped firing.
 *
 * ⚠️ `SRC_PATH` is an existing source file, not the invented name `TEST_PATH` is. The shared config's
 * TypeScript block carries `parserOptions.project`, and a path under `src/` that no file occupies is not
 * in the TS program — the parser then fails the whole lint with a fatal error and reports no rule messages
 * at all, which reads exactly like a rule that stopped firing. The content linted is the fixture's; only
 * the path is borrowed. If that file ever moves, point this at another src file.
 */
const SRC_PATH = 'src/lib/db/disconnectAllDatabases.mts'
const TEST_PATH = 'test/restrictedSyntaxFixture.mts'

const lintFixture = async (name: string, filePath: string = TEST_PATH) => {
	const code = await readFile(new URL(`${name}.mts.fixture`, FIXTURES), 'utf8')
	const [result] = await new ESLint().lintText(code, { filePath })

	return (result?.messages ?? []).filter((message) => message.ruleId === 'no-restricted-syntax')
}

describe('the no-restricted-syntax block fires on every shape it names', () => {
	it.each([
		['assignment-reject-unauthorized', TLS_MESSAGE],
		['property-reject-unauthorized', TLS_MESSAGE],
		['computed-property-reject-unauthorized', TLS_MESSAGE],
		['send-default-pii', PII_MESSAGE],
		['member-node-tls-reject-unauthorized', TLS_MESSAGE],
		['literal-node-tls-reject-unauthorized', TLS_MESSAGE],
		['max-incoming-request-body-size', BODY_MESSAGE],
		['before-send-without-transaction', HOOKS_MESSAGE]
	])('reports %s exactly once', async (fixture, expected) => {
		const messages = await lintFixture(fixture)

		expect(messages).toHaveLength(1)
		expect(messages[0]?.message).toContain(expected)
		expect(messages[0]?.severity).toBe(2)
	})
})

/*
 * `KEYGRIP_KEY_1`/`KEYGRIP_KEY_2` stopped being read when ADR-034 moved the signing keys into a wrapped
 * Redis record. Reading one here again would sign cookies the other four services cannot verify, and the
 * only symptom is a browser that is silently logged out — so the names are refused rather than merely
 * absent. Two selectors: `process.env.X` parses as an Identifier, `process.env['X']` as a Literal.
 *
 * Scoped to `src/**` because `index.unit.test.mts` asserts those very names are NOT in
 * `REQUIRED_ENV_VARS`. A repo-wide ban would refuse the test that proves the story.
 */
describe('the KEYGRIP_KEY_ ban is scoped to src/**', () => {
	it.each(['keygrip-key-member', 'keygrip-key-literal'])('reports %s exactly once under src/', async (fixture) => {
		const messages = await lintFixture(fixture, SRC_PATH)

		expect(messages).toHaveLength(1)
		expect(messages[0]?.message).toContain(KEYGRIP_MESSAGE)
		expect(messages[0]?.severity).toBe(2)
	})

	it.each(['keygrip-key-member', 'keygrip-key-literal'])('stays silent on %s under test/', async (fixture) => {
		expect(await lintFixture(fixture)).toStrictEqual([])
	})

	// The negative half: both selectors are anchored on `process.env`, so the KEK the services really do
	// read is untouched, and so is the `KEYGRIP_KEY_BYTES` constant a prefix match on the bare name would
	// have caught.
	it.each([SRC_PATH, TEST_PATH])('reports nothing on the compliant KEK read at %s', async (filePath) => {
		expect(await lintFixture('keygrip-kek-compliant', filePath)).toStrictEqual([])
	})

	// ⚠️ The src-scoped config object sets `no-restricted-syntax` a second time, and a later flat-config
	// object naming the same rule discards the earlier options outright rather than merging them. Drop the
	// spread that carries the shared entries into it and every selector above silently stops firing inside
	// src/** — the half of the codebase they exist for. This comparison needs no fixture per entry, so it
	// cannot go stale as entries are added.
	it('gives src/** every entry test/ has, plus the keygrip pair and the write ban, and nothing else', async () => {
		const entriesAt = async (filePath: string) => {
			const config = await new ESLint().calculateConfigForFile(filePath)
			const [, ...entries] = config.rules['no-restricted-syntax'] as [number, ...Record<string, string>[]]

			return entries
		}

		const shared = await entriesAt(TEST_PATH)

		expect(await entriesAt(SRC_PATH)).toStrictEqual([
			...shared,
			{
				selector: "MemberExpression[object.object.name='process'][object.property.name='env'][property.name=/^KEYGRIP_KEY_/]",
				message: expect.stringContaining(KEYGRIP_MESSAGE) as unknown as string
			},
			{
				selector: "MemberExpression[object.object.name='process'][object.property.name='env'][property.value=/^KEYGRIP_KEY_/]",
				message: expect.stringContaining(KEYGRIP_MESSAGE) as unknown as string
			},
			{
				selector:
					'ObjectExpression > Property[key.name=/^disabled(By|Reason)?$/], ObjectExpression > Property[key.value=/^disabled(By|Reason)?$/], AssignmentExpression[left.property.name=/^disabled(By|Reason)?$/], AssignmentExpression[left.property.value=/^disabled(By|Reason)?$/]',
				message: expect.stringContaining(DISABLED_MESSAGE) as unknown as string
			}
		])
		expect(shared.some((entry) => entry.selector.includes('KEYGRIP_KEY_'))).toBe(false)
		expect(shared.some((entry) => entry.selector.includes('disabled'))).toBe(false)
	})
})

/*
 * ADR-044, the same scoping shape as the keygrip ban above and for the reason the approval gate uses one
 * tier over.
 *
 * Suspension is the admin's instrument at both ends: the Admin tier raises it and the Admin tier is
 * the only hand that lifts it. A service on this tier able to write any `disabled*` field could clear a
 * sanction standing against the account whose token it is renewing.
 *
 * What is refused is the write. The read is the enforcement — the refresh projection carries `disabled`
 * so `findAccountForSession` can re-run `checkUserAuthorizationDisDel` over it, which is what ends a
 * suspended customer's session within one access-token lifetime — so a rule firing on a read would fire
 * on the reason the flag works at all.
 */
describe('the disabled* write ban is scoped to src/**', () => {
	// Four write shapes, because a `Property`-only rule passes the assignment the telemetry audit actually
	// found, and a quoted key parses to a `key.value` where the plain one has a `key.name`.
	it.each([
		'disabled-no-write-property',
		'disabled-no-write-string-key',
		'disabled-no-write-assignment',
		'disabled-no-write-computed-assignment'
	])('reports %s exactly once under src/', async (fixture) => {
		const messages = await lintFixture(fixture, SRC_PATH)

		expect(messages).toHaveLength(1)
		expect(messages[0]?.message).toContain(DISABLED_MESSAGE)
		expect(messages[0]?.severity).toBe(2)
	})

	// Not a loophole — the integration suite seeds a suspended customer to prove the gate refuses one,
	// and a seed is an object literal like any other. A rule that refused it would delete the proof that
	// the gate works, which is worth more than banning a write no test performs.
	it.each(['disabled-no-write-property', 'disabled-no-write-assignment'])('stays silent on %s under test/', async (fixture) => {
		expect(await lintFixture(fixture)).toStrictEqual([])
	})

	// The read shapes at the path where the ban is strictest: the space-separated projection this
	// service really carries, the comparison the gate makes, the destructure over a document just read,
	// the interface that read is typed against, and prose naming the fields.
	it.each([SRC_PATH, TEST_PATH])('reports nothing on the reads and the projection at %s', async (filePath) => {
		expect(await lintFixture('disabled-no-write-compliant', filePath)).toStrictEqual([])
	})
})

describe('the block stays silent on the shape the services carry', () => {
	it('reports nothing on the compliant init options', async () => {
		expect(await lintFixture('compliant')).toStrictEqual([])
	})

	// Every shared selector still fires at a src path, which is the same guarantee the structural
	// comparison above makes, driven through the linter rather than through the config object.
	it.each([
		['send-default-pii', PII_MESSAGE],
		['assignment-reject-unauthorized', TLS_MESSAGE]
	])('still reports %s under src/, so the shared entries survived the second config object', async (fixture, expected) => {
		const messages = await lintFixture(fixture, SRC_PATH)

		expect(messages).toHaveLength(1)
		expect(messages[0]?.message).toContain(expected)
	})
})
