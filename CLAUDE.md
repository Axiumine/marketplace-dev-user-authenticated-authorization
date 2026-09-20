# marketplace-dev-user-authenticated-authorization

Backend svc 8 of 9. User tier, authorization concern. Port 4031, endpoint
`/user-authenticated-authorization`. One mutation: `refresh`.

**Read parent first** — [`../../../CLAUDE.md`](https://github.com/Axiumine/fullstack-marketplace-blueprint/blob/main/CLAUDE.md)
Tier/concern split, port table, terminology, auth model live there. Not here.

| Need | File |
|---|---|
| what this svc is, suite shape | [`README.md`](./README.md) |
| hook internals, gate order, node selection, mutation-gate rationale, the ShopOwner-svc diff, unit suite | [`REPO.md`](./REPO.md) |
| why the three authz svcs stay three | parent [`docs/decisions/authorization-service-consolidation.md`](https://github.com/Axiumine/fullstack-marketplace-blueprint/blob/main/docs/decisions/authorization-service-consolidation.md) |
| GitNexus rules, this repo's registry name (`marketplace-dev-user-authenticated-authorization`) | [`AGENTS.md`](./AGENTS.md) |

Business queries → `marketplace-dev-user-authenticated-resource` (4032). Logout →
`marketplace-dev-authenticated-logout` (4030), all three tiers.

## ⚠️ NEVER run the mutation gate by hand

`yarn test:mutation` is **hook-only** — `pre-push` calls it, nothing else does, not even to check one
file or confirm a survivor is fixed. Never invoke `stryker` directly either. Rationale and how to
reproduce a survivor without running the gate: [`REPO.md`](./REPO.md).

## ⚠️ Decided, not re-openable

Most of this service's body lives in `marketplace-common`, deliberately. **Do not re-inline the helpers,
and do not merge the three authorization services into one** — that merge is a decision the user has
already taken, against. Full survey: [`README.md`](./README.md).

## Traps

- **`refresh` rotates rather than re-issues.** The refresh token the call was made with is deleted, so a
  stolen copy is worthless the moment the legitimate client refreshes. The wire test asserts the exact
  `del` key.
- **`TIER.user` is asserted, not trusted from the session.** A session with no `tier`, or the wrong one,
  is refused — fail closed. Do not remove the assertion or read it as redundant with the `_id` lookup.
- **The cookie-signing keys need no hand agreement with `marketplace-dev-public-authorization`.** Since
  ADR-034 both read the one Redis record at `<REDIS_KEY>keygrip`; a service that cannot unwrap it refuses
  to boot rather than signing with keys of its own.
- **A value containing whitespace must be quoted in the environment file, in single quotes.** dotenv
  truncates a bare value at the first space with no error, and double quotes expand `\n`/`\r` escapes.

## Tests & gates

100% on all four coverage metrics, mutation score 100 — never narrow `test:cov` to one project to make it
green (rule below). Suite internals: [`REPO.md`](./REPO.md). commit → secret guard, lint, types,
coverage, Qodana. push → same + semgrep (SAST) + trivy (dependency advisories) + mutation, all blocking. Why:
[`REPO.md`](./REPO.md).

## Rules

- **Never commit on `main`.** Branch first: `git switch -c <type>/<slug>`. Merge = user decision alone.
- Merged → delete branch: `git branch -d <slug>`. `-d` only. `-D` never.
- **No remote. Push-on-request:** no `git push` unless the user asked for it in that message.
- **Never lower a coverage or mutation threshold, and never remove a gate.** Threshold miss → write the
  missing test. Bypasses (`SKIP_QODANA=1`, `--no-verify`) are gate removals: use only when the user says so.
- **Tabs, not spaces.** eslint + prettier both enforce.
- **English only** — identifiers, comments, fixtures. No exception.
- Domain query/mutation → **resource** svc. Token lifecycle → **authorization** svc.
- **Run `impact({target, repo})` before editing a symbol and `detect_changes()` before committing**;
  `repo:` is mandatory and must be a `marketplace*` registry name.
