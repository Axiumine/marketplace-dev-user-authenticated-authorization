# marketplace-dev-user-authenticated-authorization

Backend svc 8 of 9. User tier, authorization concern. Port 4031, endpoint
`/user-authenticated-authorization`. One mutation: `refresh`.

**Read parent first** — [`../../../CLAUDE.md`](https://github.com/Axiumine/fullstack-marketplace-blueprint/blob/main/CLAUDE.md)
Tier/concern split, port table, terminology, auth model live there. Not here.

| Need | File |
|---|---|
| what this svc is, suite shape, env-repair history | [`README.md`](./README.md) |
| hook internals, gate order, node selection | [`REPO.md`](./REPO.md) |
| why the three authz svcs stay three | parent [`docs/decisions/authorization-service-consolidation.md`](https://github.com/Axiumine/fullstack-marketplace-blueprint/blob/main/docs/decisions/authorization-service-consolidation.md) |

Business queries → `marketplace-dev-user-authenticated-resource` (4032). Logout →
`marketplace-dev-authenticated-logout` (4030), all three tiers.

## Decided, not re-openable

⚠️ **Most of this service's body lives in `marketplace-common`, deliberately. Do not re-inline the
helpers, and do not go the other way and merge the three authorization services into one.** The merge is
a decision the user has already taken, against. The survey behind it, including the two rejected
alternatives, is the decision doc named above.

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

## Traps

- **The introspection bypass is narrower here than in the resource services.** It is consulted only
  *after* `verifySignedRefreshToken` has returned a token, so an `x-introspectioncode` with no cookie is
  still a 412. The code stands in for a *session*, never for the signature, and a leaked code alone cannot
  be replayed. `index.unit.test.mts` asserts both halves.
- **`refresh` rotates rather than re-issues.** The refresh token the call was made with is deleted, so a
  stolen copy is worthless the moment the legitimate client refreshes. The wire test asserts the exact
  `del` key.
- **`KEYGRIP_KEY_1` / `KEYGRIP_KEY_2` must equal `marketplace-dev-public-authorization`'s**, and
  `INTROSPECTION_CODE` must equal the other eight services'. Nothing tests either pairing — each service
  signs and verifies with itself in its own suite — so a mismatch surfaces only as a 401 on every customer
  refresh, or as a service-to-service bypass that fails in both directions.
- **A value containing whitespace must be quoted in the environment file, in single quotes.** dotenv
  terminates a bare value at the first space, hands back the truncated prefix and reports no error — which
  is how a keygrip key silently became a 76-character slice of its 89-character self. Not double quotes:
  dotenv expands `\n` and `\r` escapes inside those.

## Tests

Eight files, 71 tests, 100% on all four coverage metrics, mutation score 100.

`index.unit.test.mts` boots the real server with `createServer()` on port 0 and drives `/health`, an
unknown path, a signed refresh over the endpoint, the cross-tier refusal and a bare GET refused by
`csrfPrevention`, with Redis and the `User` model stubbed. It covers the dispatch middleware; it is not a
replacement for the integration project.

**Do not lower a threshold, and do not narrow `test:cov` to one project, to make it green.**

## Rules

- **Never commit on `main`.** Branch first: `git switch -c <type>/<slug>`. Merge = user decision alone.
- Merged → delete branch: `git branch -d <slug>`. `-d` only. `-D` never.
- **No remote.** Push-on-request: no `git push` unless the user asked for it in that message.
- **Never lower a coverage or mutation threshold, and never remove a gate.** Threshold miss → write the
  missing test. Bypasses (`SKIP_QODANA=1`, `--no-verify`) are gate removals: use only when the user says so.
- Tabs, not spaces. eslint + prettier both enforce.
- English only — identifiers, comments, fixtures. No exception.
- Domain query/mutation → **resource** svc. Token lifecycle → **authorization** svc.

## Gates

commit → secret guard, lint, coverage, Qodana. push → same + mutation. All blocking. Why: [`REPO.md`](./REPO.md).

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **marketplace-dev-user-authenticated-authorization**. Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/marketplace-dev-user-authenticated-authorization/context` | Codebase overview, check index freshness |
| `gitnexus://repo/marketplace-dev-user-authenticated-authorization/clusters` | All functional areas |
| `gitnexus://repo/marketplace-dev-user-authenticated-authorization/processes` | All execution flows |
| `gitnexus://repo/marketplace-dev-user-authenticated-authorization/process/{name}` | Step-by-step execution trace |

## Cross-Repo Groups

This repository is listed under GitNexus **group(s): marketplace-platform** (see `~/.gitnexus/groups/`). For cross-repo analysis, use MCP tools `impact`, `query`, and `context` with `repo` set to `@<groupName>` or `@<groupName>/<memberPath>` (paths match keys in that group’s `group.yaml`). Use `group_list` / `group_sync` for membership and sync. From the project root: `node .gitnexus/run.cjs group list`, `node .gitnexus/run.cjs group sync <name>`, `node .gitnexus/run.cjs group impact <name> --target <symbol> --repo <group-path>` (the `.gitnexus/run.cjs` path is repo-root-relative).

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
