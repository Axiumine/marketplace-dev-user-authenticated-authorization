# marketplace-dev-user-authenticated-authorization

Token lifecycle for the **customer** tier — `User`, the end customer who places orders. Port **4031**,
endpoint `/user-authenticated-authorization`, one mutation: `refresh`.

No business queries live here; those are in `marketplace-dev-user-authenticated-resource` (4032). Logout
gets no service of its own either — `marketplace-dev-authenticated-logout` (4030) deletes sessions by
token content and never inspects which model minted them, so all three tiers share it unchanged.

## Why so little code is in this repo

Most of this service's body lives in `marketplace-common`, and has since 4.4.0.

It was copied from `marketplace-dev-authenticated-authorization` (4029) and the copy was near-exact, so on
2026-08-07 the shared part moved into `resolveAuthorizationSession`, `findAccountForSession` and
`refreshSessionTokens`, while the three services, three ports and three crash domains stayed exactly as
they were. The survey behind that choice — including the two options that were rejected and why — is
`docs/decisions/authorization-service-consolidation.md` in the parent workspace.

Both directions are closed. The helpers are not to be re-inlined, and the three services are not to be
merged into one: the merge is a decision the user has already taken, against.

## What remains here

`CLAUDE.md` carries the three tier-specific differences in full — no onboarding, the hardcoded `TIER.user`
and its assertion order, and why `emailVerify.valid` is not re-checked on refresh.

## The suite

Eight files, 71 tests, 100% on all four coverage metrics and a 100.00 mutation score — seven unit files
(56 tests) plus the integration one (15). The "skip all tests" instruction this repo was built under was
revoked by the user on 2026-08-06 and the suite was written from the harness up.

`yarn test:cov` ran for the first time on 2026-08-07, and until that day it had never executed a single
integration test. The `integration` project aborted in `globalSetup` before collecting anything, because
this machine's environment file was a copy of an unrelated old project's: five `MONGO_TEST_*` keys were
empty, so `assertTestMongoEnv` refused to build a URL. They are filled in now, and the two database users
they authenticate as were provisioned with the loop in `marketplace-db-setup/setup/mongodb.js` — dropping
`dbMarketplaceTestUserAuthz` does **not** remove them, MongoDB keeps users in `admin.system.users`.

Three more keys in the same file were wrong rather than missing. Each failed somewhere far from its cause,
which is why they are worth recording:

- `KEYGRIP_KEY_1` / `KEYGRIP_KEY_2` did not match `marketplace-dev-public-authorization`'s. That service
  is where `loginUser` signs the customer's refresh cookie and this one has to verify the signature, so
  with different keys every customer refresh returned 401 — and no test covers the pairing, because each
  service signs and verifies with itself in its own suite.
- `MONGODB_URI` pointed at `testRnApollo`, a leftover database from that other project, with no
  `authSource`. The `user` collection the migrations create lives in `dbMarketplaceDev`.
- `INTROSPECTION_CODE` differed from the seven other services', which breaks the service-to-service bypass
  in both directions.

## Qodana

Clean here as of 2026-08-07 — the token was added and the cloud project is `B5NEV`, so `SKIP_QODANA=1` is
no longer needed. Since the environment file was repaired the hooks run it like everywhere else, so it
needs invoking by hand only after a `--no-verify` commit — the one gate a bypass silently drops that
nothing else re-runs:

```sh
SKIP_TESTS=1 ./qodana.sh --results-dir .qodana/results
```

after `yarn test:cov` has written the lcov it reuses.

## Related files

| Topic | File |
|---|---|
| rules for agents working in this repo | `CLAUDE.md` |
| git hooks, gate order, node selection | `REPO.md` |
| the whole platform — tiers, ports, terminology | parent `CLAUDE.md` |
