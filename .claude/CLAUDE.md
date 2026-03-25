# Aegis — Claude Project Instructions


## Branch Strategy

`local-testing` and `main` are kept **identical** with one exception:

| Branch | `config/database.yml` host |
|--------|---------------------------|
| `main` | `100.69.88.107` (Tailscale — live server PostgreSQL) |
| `local-testing` | `localhost` |

**Rule**: After every merge between branches, restore the correct host for that branch. No other differences are allowed between branches.

## Database

- Database: `vulnerability_scanner`
- Schema: `vuln_scanner` (all environments — development, test, production)
- Username: `aegis`
- Local Mac: `aegis` must have SUPERUSER (`ALTER USER aegis WITH SUPERUSER;`). Rails needs it to disable FK triggers when loading test fixtures (`fixtures :all`).

## Server

The live server runs at `100.69.88.107` over Tailscale. `railsRestart` does:
`git pull → bundle install → db:migrate → rails test → rails server`

## Test Setup

- ONE database (`vulnerability_scanner`), ONE schema (`vuln_scanner`), for all environments. There is no test database, no test schema, no `vuln_scanner_test`. Never create one.
- Tests are run with `bundle exec rails test` — never tell the user to type `RAILS_ENV=test`.
- `test/test_helper.rb` wraps the entire test run in an outer PostgreSQL transaction. `Minitest.after_run` rolls it back — dev data (users, orgs, etc.) is fully preserved after tests complete.
- Each individual test is also wrapped in a savepoint (`use_transactional_tests = true`, Rails default) — per-test data is cleaned up after each test.
- `parallelize(workers: 1)` must stay set — required for the single-connection outer transaction approach.

### PostgreSQL sequences are NON-transactional
`nextval`/`setval` side-effects persist even if the surrounding transaction rolls back. If stale fixture rows exist from a pre-fix test run, sequence conflicts occur on the next login (`PG::UniqueViolation sessions_pkey`). One-time fix:
```sql
TRUNCATE vuln_scanner.sessions RESTART IDENTITY;
```

### schema.rb `create_schema` is NOT idempotent
Rails auto-generates `create_schema "vuln_scanner"` (no `IF NOT EXISTS`). Never run `db:schema:load` on an existing database — it will fail with `PG::DuplicateSchema`. Use `db:migrate` only for ongoing development.

### Never propose
- A separate test schema or test database
- `schema_search_path` overrides in the test block of `database.yml`
- `RAILS_ENV=test` commands for the user to type manually
