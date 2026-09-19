# Repository mechanics

How this repo's git plumbing behaves, and why. Nothing here changes what you write — it explains what
happens when you commit, push, or watch a gate fail. [`CLAUDE.md`](./CLAUDE.md) carries the rules themselves.

## Hooks

`git push` runs `.githooks/pre-push`, a blocking **six**-step gate: `yarn semgrep:ci` (Semgrep SAST over the
sources, vendored rules, pinned image, `--network none`), then trivy (dependency advisories, HIGH and
CRITICAL, production tree only), then `yarn lint:check` (eslint, then
`prettier --check`, both over the whole tree), then `yarn test:cov` (100% on every metric), then
`yarn test:mutation` (Stryker, `thresholds.break: 100`), then Qodana (`./qodana.sh`, gated by
`qodana.yaml`: coverage 100 total / 100 fresh and the license audit). Keep the hook executable: git skips
a non-executable hook with only a hint, so the gate disappears without ever failing.

⚠️ **Qodana is not what covers dependencies here, and the list above used to say it was.** The inspection
it runs is `VulnerableLibrariesLocal`, an offline heuristic that queries no advisory feed and reports zero
on every repo on this platform; the class that does query one ships in the same image and is in no
profile. The trivy step is the check that reports — it reads `yarn.lock` natively, suppresses
devDependencies, and blocks on HIGH or CRITICAL with the CVE id and the fixed version. Bypass for a Docker
or network outage, never for a finding: `SKIP_TRIVY=1 git push`.

`git commit` runs `.githooks/pre-commit`, which is the secret guard *and* three of those six — lint,
coverage, Qodana. Semgrep, trivy and mutation are pre-push only.

Semgrep and trivy lead because they are the two cheap ones — about three seconds and, with the
vulnerability database already pulled, under one — against the minutes the rest take together, so a rule
violation or an advisory is reported before anything slow runs.
Lint leads the four that follow because it is the cheapest of them and the only one that can fail on a
file the others are perfectly happy with — the next `yarn lint` would rewrite it anyway. It was
ungated for a long time, and so were `eslint.config.js`, `.prettierrc` and `.prettierignore`: none of
the three was in the hook's `RELEVANT_PATHS`, so a commit touching only them skipped every gate there
is. All three are in the filter now.

## Why Qodana runs in both hooks

**`git merge --no-ff` never fires `pre-commit`** — git runs that hook for `git commit` only — so in the
branch → commit → merge → push flow the merge commit, the one revision that actually reaches origin,
is the single commit no pre-commit scan ever sees. Two individually clean branches can merge into a
tree that is not.

The second reason is Qodana Cloud. It files every report under the branch it was produced on, and
pre-commit always runs on the feature branch *before* the commit exists — so a repo gated only there
can never produce a `main`-tagged report, `main` is not offered as the project's default branch, and
the "new problems" baseline has nothing stable to compare against. pre-push runs after the merge, on
main, which is the revision the baseline wants. Both scans hand `qodana.sh` `SKIP_TESTS=1` so the
coverage report the preceding gate just wrote is reused rather than regenerated with its exit code
swallowed.

## Node selection

Ahead of every gate the hook selects node, reading `engines.node` from `package.json` and switching via
nvm. The gates shell out to yarn and yarn's `engines` check is a hard exit 1, so without it a push from
a shell on the machine default node dies *before* the first gate, under that gate's banner — which is
how a node mismatch first read as a type error. Every repo's `pre-push` carries that block, and so does
every `pre-commit`, since all of them run tests.

## Bypasses

`SKIP_QODANA=1` (scan only — coverage and mutation still gate) · `git commit --no-verify` /
`git push --no-verify` (the whole hook). Both are gate removals. See [`CLAUDE.md`](./CLAUDE.md) for when they may be
used, which is: when the user says so, and not otherwise.

## Why the mutation gate is hook-only

This does not weaken anything: the threshold stays 100, `pre-push` still blocks, and no survivor is ever
answered by lowering a number. What changes is **who starts the run**. A full pass costs tens of minutes
and holds the whole machine at 28 workers while it lasts, so an on-demand run is time taken from the
person waiting for the work.

Go through the package script if a run is ever authorised — never `npx stryker run`, which skips whatever
the script sets up around it.

A survivor is answered by writing the test it names and letting the next push run the gate. If a mutant
has to be reproduced first, apply it by hand in the source and run `yarn test` — that is seconds, it
names the tests that should have failed, and it costs nobody the machine.

## Not a rename of the ShopOwner service

Copied from 4029. Three differences, none of them an omission to "correct" back:

- **No onboarding.** The ShopOwner svc imports `makeOnboardingData` and branches on `login.onboardingStep`
  / `login.onboardingDone` / `login.firstLogin`. A customer has none → `tokenInfoUser` projects three
  fields fewer than `tokenInfoShopOwner`, access-token hash is `_id`, `email`, `tier` and nothing else, and
  `IRedisDataUserCommon` has nowhere to put a step.
- **`TIER.user`**, hardcoded at the one `resolveAuthorizationSession` call, which asserts it. All nine svcs
  share one `REDIS_KEY` prefix, so a well-formed refresh session found under this key may have been minted
  for another tier. The assertion runs *before* the `_id` is looked up: that lookup is not a substitute, it
  only fails by accident, when the foreign id happens not to exist in `user` too. A session with no `tier`
  predates the discriminator and is refused as well — fail closed. `assertTier` itself moved into the
  shared helper in 4.4.0; the *constant* stays here, because a svc that could be told its own tier by a
  caller asserts nothing.
- **`emailVerify.valid` is not re-checked on refresh.** `loginUser` on 4028 refuses to mint a session for
  an unconfirmed address in the first place, and nothing on the platform ever un-confirms one. `deleted`
  and `disabled` *can* flip after login, which is why `checkUserAuthorizationDisDel` runs on every refresh:
  it makes disabling an account take effect within one access-token lifetime instead of one refresh-token
  lifetime.

`ctx.state.user` = `TAuthorizationSession<IRedisDataUserCommon>` — the helper's own return type, not a
restatement of it. Middleware assigns with no cast; context type and helper cannot drift.

## The unit suite

`index.unit.test.mts` boots the real server with `createServer()` on port 0 and drives `/health`, an
unknown path, a signed refresh over the endpoint, the cross-tier refusal and a bare GET refused by
`csrfPrevention`, with Redis and the `User` model stubbed. It covers the dispatch middleware; it is not a
replacement for the integration project.
