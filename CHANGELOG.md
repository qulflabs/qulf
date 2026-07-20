## v0.1.0b2 (2026-07-20)

### Feat

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

- **routing**: update methods type hint to sequence
- **routing**: update methods type hint to sequence
- **rate_limit**: simplify reset_in calculation logic
- **plugin**: remove redundant auth checks
- **adapter**: optimize session deletion and coverage
- **config**: setup commitizen and pre-commit
