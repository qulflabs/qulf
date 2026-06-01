# 🛡️ Qulf

<p align="center">
  <em>The comprehensive, framework-agnostic, and heavily typed authentication library for Python.</em><br/>
  <em>Inspired by <a href="https://better-auth.com" target="_blank">Better-Auth</a>.</em>
</p>

<p align="center">
<a href="https://pypi.org/project/qulf" target="_blank">
    <img src="https://img.shields.io/pypi/v/qulf?color=%2334D058&label=pypi%20package" alt="Package version">
</a>
<a href="https://pypi.org/project/qulf" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/qulf.svg?color=%2334D058" alt="Supported Python versions">
</a>
<a href="https://github.com/pitachro/qulf/blob/main/LICENSE" target="_blank">
    <img src="https://img.shields.io/github/license/pitachro/qulf.svg" alt="License">
</a>
<a href="https://codecov.io/gh/pitachro/qulf" target="_blank">
    <img src="https://codecov.io/gh/pitachro/qulf/branch/main/graph/badge.svg" alt="Coverage">
</a>
</p>

---

## The Problem
The Python ecosystem's authentication is deeply fragmented. If you use Django, you use Django Auth. If you use FastAPI, you use `fastapi-users`. If you use Flask, you use `Flask-Login`. 

If you decide to switch frameworks or databases, you have to rewrite your entire authentication layer. Furthermore, adding modern features like Passkeys, Two-Factor Auth (2FA), or Magic Links requires cobbling together unmaintained third-party packages.

## Where Qulf comes in
**Qulf** is built on three decoupled pillars:
1. **The Core**: Pure, heavily typed (Pydantic v2) Python that handles cryptography, validation, and business logic.
2. **Database Adapters**: Agnostic adapters for SQLAlchemy, SQLModel, MongoDB and many more to come etc.
3. **Framework Adapters**: Plug-and-play wrappers for FastAPI, Django, Litestar, Flask and new ones being added frequently.

### Key Features
- 🔌 **Framework Agnostic** - Works seamlessly with modern async frameworks (FastAPI, Litestar) and legacy sync frameworks.
- 🗄️ **Database Agnostic** - Bring your own ORM (SQLAlchemy, Prisma, SQLModel, etc.).
- 🧩 **Plugin-Driven** - Keep the core light. Add OAuth, Passkeys, Magic Links, and 2FA via simple plugins.
- 🔒 **Secure by Default** - Industry-standard session management, argon2 hashing, and automatic CSRF protection.
- ⌨️ **Fully Typed** - Built entirely on Pydantic V2 for world-class IDE autocomplete and strict type safety.

---

## Quickstart

### 1. Installation
Install the core library along with the adapters you plan to use:

```bash
# Using uv (recommended)
uv add qulf[sqlalchemy,fastapi]

# Or pip
pip install "qulf[sqlalchemy,fastapi]"
```

### 2. Define your Auth Client
Configure `Qulf` once. It knows nothing about your HTTP framework at this stage.

```python
# auth.py
from qulf import Qulf
from qulf.adapters.sqlalchemy import SQLAlchemyAdapter
from qulf.plugins import magic_link, two_factor

# 1. Provide your database session
db_adapter = SQLAlchemyAdapter(session_maker)

# 2. Instantiate Qulf
auth = Qulf(
    database=db_adapter,
    email_and_password={"enabled": True},
    plugins=[
        magic_link(send_email_func=my_email_sender)
    ]
)
```

### 3. Plug into your Framework
Because Qulf is framework-agnostic, integrating it as simple as passing your configured `auth` instance to a framework wrapper.

**FastAPI Example:**
```python
# main.py
from fastapi import FastAPI
from qulf.frameworks.fastapi import serve_qulf
from auth import auth

app = FastAPI()

# Mount the auth router (exposes /api/auth/sign-in, /api/auth/sign-out, etc.)
app.include_router(serve_qulf(auth), prefix="/api/auth")
```

---

## 🎮 Interactive Demo

We have built a fully featured, modern single-page application (SPA) demo showcasing Qulf working with:
* **FastAPI** (API endpoints & session cookies)
* **SQLAlchemy** (async SQLite backend)
* **Magic Link Plugin** (passwordless login)

To run the interactive demo:

1. **Install dependencies** (if not already done):
   ```bash
   mise run setup
   ```
2. **Start the demo server**:
   ```bash
   mise run demo
   ```
3. Open your browser and navigate to **`http://localhost:8000`**. You can register a user, sign in with credentials, or generate and verify passwordless magic links!

---

## 🗺️ Roadmap (v0.1.0)
Qulf is currently in active development. Here is the path to `1.0.0`:

- [x] **Phase 1: MVP** (Async Core, SQLAlchemy Adapter, FastAPI Framework, Email/Password, Sessions)
- [-] **Phase 2: Plugin Engine** (Hooks system, Magic Links, 2FA/TOTP)
- [ ] **Phase 3: OAuth2** (GitHub, Google, Apple integrations)
- [ ] **Phase 4: Expansion** (Litestar, Django, SQLModel, MongoDB)

---

## 🛠️ Contributing

We welcome contributions! Qulf uses a modern and fast development stack powered by Rust-based tools.

### Prerequisites
You only need to install [mise-en-place](https://mise.jdx.dev/). `mise` will automatically manage Python, `uv`, and all environment variables for you.

### Dev Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/pitachro/qulf.git
   cd qulf
   ```
2. Set up the environment and install dependencies:
   ```bash
   mise run setup
   ```
3. Run tests:
   ```bash
   mise run test
   ```

To see all available development commands, simply type:
```bash
mise tasks
```

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.