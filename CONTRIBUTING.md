# Contributing to Qulf

First off, thank you for considering contributing to **Qulf**! 

Qulf is designed to be the Python equivalent of TypeScript's `better-auth` or `auth.js`. We prioritize **Developer Experience (DX)**, **strict type safety**, and **framework agnosticism**. 

To maintain the high quality of this library, we have strict guidelines for architecture, testing, and code style. Please read this guide carefully before opening a Pull Request.

---

## Architecture

Qulf is strictly decoupled into four layers. When adding features, ensure your code lives in the correct layer:

1. **The Core (`src/qulf/core.py`)**: Pure, framework-agnostic Python. Handles crypto, validation, session management, and hooks. Configured via `QulfConfig`.
2. **Database Adapters (`src/qulf/adapters/`)**: Abstract Base Classes defining data contracts. (e.g., `SQLAlchemyAdapter`, `MotorAdapter`, `SQLModelAdapter`).
3. **Framework Wrappers (`src/qulf/frameworks/`)**: Translates Qulf's generic `QulfRoute` into native framework endpoints (e.g., FastAPI, Django, Litestar, Flask).
4. **Plugins (`src/qulf/plugins/`)**: The powerhouse of Qulf. Plugins expose framework-agnostic routes, dynamically inject database columns, and intercept core flows via Lifecycle Hooks.

---

## Local Development Setup

We use [`mise`](https://mise.jdx.dev/) for managing environments and tasks, and [`uv`](https://github.com/astral-sh/uv) for lightning-fast Python dependency management.

### Prerequisites
- Install `mise` on your machine.
- Python 3.10+ (managed via `mise`).

### Step-by-Step Setup

1. **Fork & Clone**
   ```bash
   git clone https://github.com/qulflabs/qulf.git
   cd qulf
   ```

2. **Initialize Environment**
   Let `mise` and `uv` handle the virtual environment and install all core, framework, and testing dependencies:
   ```bash
   mise run setup or uv sync
   ```

3. **Install Pre-Commit Hooks**
   We use `pre-commit` to enforce formatting, linting, type-checking, and test coverage before you can push.
   ```bash
   uv run pre-commit install
   ```

---

## Development Workflow

We have mapped the most common commands into `mise.toml` for developer convenience:

- **Format Code**: `mise format` (Runs `ruff` formatting)
- **Lint & Types**: `mise lint` (Runs `ruff` linter and `mypy` strict typing)
- **Run Tests**: `mise tests` (Runs `pytest`)
- **Run Tests w/ Coverage**: `mise tests:cov` (Generates a terminal missing-lines report)
- Run **mise tasks** to get a list of all tasks that are available

---

## Quality Mandates

### 1. ~99% Coverage
We enforce **1~99% test coverage** via Codecov. 
- A Pull Request **MIGHT be rejected** if it drops coverage by a substantial amount(subjective(don't let it drop at all if possible)).
- You must test both the "happy path" and all error/exception branches.
- Use `pytest` fixtures to keep tests DRY.

### 2. Strict Typing
- All code must be strongly typed.
- We use Pydantic V2 for runtime validation and settings.
- `mypy` is configured strictly (`strict = true`). No untyped functions or implicit `Any` fallbacks are allowed.

### 3. Commenting
Good code explains itself. **Write comments only when they add information that cannot be inferred from the code.**

**DO comment:**
- A non-obvious design decision.
- A workaround for a library or platform limitation.
- A security, correctness, or compatibility concern (e.g., `# Prevent timing attacks`).

**Format:**
- Keep it on one line whenever practical.
- Explain **why**, not **what**.
- Never narrate execution.

---

## Git Workflow & Commits

### Branch Naming Convention
Whenever you start a new feature or task, map it to a tracking issue. Use the following branch naming format:
- Features: `feature/<issue-id>-<feature-name>`
- Bugfixes: `fix/<issue-id>-<bug-name>`
- Chores/Docs: `chore/<issue-id>-<chore-name>`

### Conventional Commits
We use **Commitizen** (`cz`) to manage semantic versioning. Your commits must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format.

When you are ready to commit, do not use `git commit -m`. Instead, use:
```bash
uv run cz commit
```
This will prompt you through an interactive CLI to build a perfectly formatted commit message.

*Note: Our pre-push hooks will automatically run `pytest` and `mypy`. Ensure your code passes locally before pushing.*

---

## Pull Request Checklist

Before opening a PR, ensure you can check off the following:

- [ ] I have run `mise format` and `mise lint`.
- [ ] I have run `mise tests:cov` and maintained **coverage %**.
- [ ] My code uses strict type hints and passes `mypy`.
- [ ] I have added or updated documentation in the `web/` (Fumadocs) folder if necessary.

If your PR introduces a new Database Adapter, Framework, or Plugin, please tag us early for an architectural review.

Happy hacking!