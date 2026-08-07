## v0.1.0b7 (2026-08-07)

### Feat

- **flask**: add session endpoint and dependency helpers
- **litestar**: add session endpoint and dependency helpers
- **django**: add session endpoint and dependency helpers
- **fastapi**: add session endpoint and dependency helpers

### Fix

- **frameworks**: comment the unhandled server errors prevention on invalid json bodies
- **frameworks**: handle unauthorized status codes and response types

### Refactor

- **test**: refactor sqlalchemy adapter tests into test classes and fixtures
- **tests**: refactor core tests and remove obsolete coverage gap file
- **tests**: refactor rbac test suite structure and mock fixtures
- **test**: organize provider tests into test classes
- **tests**: organize rate limit tests into classes and improve type hints
- **tests**: reorganize passkey plugin tests into classes and add type hints

## v0.1.0b6 (2026-08-04)

### Feat

- **auth**: implemented PasskeyPlugin for WebAuthn support managing registration and authentication

## v0.1.0b5 (2026-08-01)

## v0.1.0b4 (2026-08-01)

### Feat

- add Flask framework support and update project roadmap in README
- **frameworks**: add flask support and tests
- **frameworks**: add flask integration
- **litestar**: add role and permission authorization guards and dependencies
- **django**: add role and permission decorators and route protection
- **fastapi**: add rbac enforcement and route protection dependencies
- **motor**: add rbac support for motor adapter
- **adapter**: add rbac support to sqlmodel adapter
- **adapter**: add role and permission support to sqlalchemy adapter
- **core**: add role-based access control and permission checks
- **adapter**: add role and permission methods to database adapter

### Refactor

- **test**: reorganize plugin test files and update adapter fixture
- **adapters**: remove adapter exports from init module

## v0.1.0b3 (2026-07-29)

### Feat

- **validators**: add user validation utility and new exceptions
- **litestar**: add password management and account deletion endpoints
- **fastapi**: add password management and account deletion endpoints
- **django**: add missing auth endpoints to django framework integration
- **adapter**: add support for user deletion and password retrieval in motor adapter
- **adapters**: implement user deletion and pluralize table names
- **core**: add email hooks and update auth error handling
- **frameworks**: add authentication request models
- **adapter**: add password-specific user retrieval methods
- **core**: add password reset, email verification, and account deletion
- **exceptions**: add user account deactivated error
- **types**: add timestamp fields to user session and account models
- **config**: add configuration schemas for deletion, password reset, and email management
- **litestar**: add litestar framework integration support
- **routing**: add httpmethod enum and update route definitions
- **litestar**: add litestar framework integration support
- **routing**: add httpmethod enum and update route definitions
- **django**: add django framework support and tests
- **django**: add django integration for qulf framework
- **core**: added a type safe get_plugin method.
- **rate_limit**: add fixed window rate limiter implementation
- **rate_limit**: add sliding window rate limiting implementation
- **adapters**: added SQLModel database adapter
- **rate_limit**: implement token bucket rate limiting
- **plugins**: add rate limiting support
- **plugins**: improve user retrieval and add type hints
- **fastapi**: add type definitions and improve endpoint signatures
- **core**: implement plugin lifecycle hooks engine (PIT-5)

### Fix

- **mise**: handle unbound variable for dry run flag
- **mise**: handle unset usage_dry_run variable safely
- **oauth**: format database integrity error message string
- **deps**: added missing dev dependency aiosqlite
- **deps**: added missing dev dependencies respx and faker
- **code**: sort export lists alphabetically
- **github**: update codecov reporting configuration
- **build**: fix coverage action failure
- **formatting**: fix formatting issue
- **formatting**: fix formatting issues
- **workflows**: update actions and optimize checkout strategy
- **rate_limit**: remove legacy rate limiter module
- **attr**: fix incorrect attribute
- **formatting**: formatting issue
- **actions**: restrict release and ci triggers
- **workflows**: update python version and optimize release actions
- **variable**: fix naming mistake
- **db**: optimize sqlalchemy session deletion logic

### Refactor

- **release**: consolidate release tasks and export cookie options
- **crypto**: parameterize session token length and format config description
- **deps**: reorganize project dependencies and groups
- **routing**: update methods type hint to sequence
- **routing**: update methods type hint to sequence
- **rate_limit**: simplify reset_in calculation logic
- **plugin**: remove redundant auth checks
- **adapter**: optimize session deletion and coverage
- **config**: setup commitizen and pre-commit
