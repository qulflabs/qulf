# Qulf

<p align="center">
  <em>The comprehensive, framework-agnostic, and heavily typed authentication library for Python.</em><br/>
  <em>Inspired by <a href="https://better-auth.com" target="_blank">Better-Auth</a>.</em>
</p>
<div align="center">

  [![Codecov](https://codecov.io/gh/qulflabs/qulf/branch/main/graph/badge.svg?token=WMNPSILZIC)](https://codecov.io/gh/qulflabs/qulf)
  [![Typing](https://img.shields.io/badge/typing-standard-4B32C3?style=flat-square)](https://github.com/microsoft/pyright)
  [![License](https://img.shields.io/github/license/qulflabs/qulf?style=flat-square)](https://github.com/qulflabs/qulf/blob/main/LICENSE)
  [![CI](https://img.shields.io/github/actions/workflow/status/qulflabs/qulf/ci.yml?branch=main&style=flat-square&logo=github)](https://github.com/qulflabs/qulf/actions)
</div>

---

## The Problem

The Python ecosystem's authentication is deeply fragmented. If you use Django, you use Django Auth. If you use FastAPI, you use `fastapi-users` . 

If you decide to switch frameworks or databases, you have to rewrite your entire authentication layer. Furthermore, adding modern features like Passkeys, Two-Factor Auth (2FA), OAuth, or Rate Limiting requires cobbling together unmaintained third-party packages.

## Our Solution

 **Qulf** is built on three decoupled pillars, allowing you to build your auth once and deploy it anywhere:
1. **The Core** : Pure, strictly typed (Pydantic V2) Python that handles cryptography, validation, and business logic.
2. **Database Adapters** : Bring your own ORM (SQLAlchemy, SQLModel, MongoDB).
3. **Framework Adapters** : Plug-and-play wrappers for FastAPI, Litestar, and Django.

### Key Features

* **Framework Agnostic** - Drop it into FastAPI, Litestar, or Django with a single line of code.
* **Database Agnostic** - Seamless SQL and NoSQL support.
* **Plugin-Driven** - Keep the core light. Add OAuth (GitHub/Google), Magic Links, and TOTP/2FA via plugins.
* **Secure by Default** - Bulletproof session management, argon2 hashing, and highly configurable Rate Limiting (Sliding Window, Token Bucket).
* **Typed & Tested** - Built with Pyright Standard typing and enforced ~99% test coverage.

---

## Quick Start

Here is how easily Qulf mounts into a modern async application:

```python
from fastapi import FastAPI
from qulf.core import Qulf, QulfConfig
from qulf.adapters.sqlmodel import SQLModelAdapter
from qulf.frameworks.fastapi import serve_qulf

# 1. Initialize your DB adapter

adapter = SQLModelAdapter(engine=my_db_engine)

# 2. Configure Qulf
auth = Qulf(
    db=adapter,
    config=QulfConfig(secret_key="<SECRET_KEY>"),  # 32 chars or more
)

# 3. Mount it to your Framework of choice!
app = FastAPI()
app.include_router(serve_qulf(auth), prefix="/auth")
```

### Ecosystem (Before v1.0.0)

Qulf ships with batteries included. Mix and match to fit your stack:

| Frameworks       | Databases             | Plugins          |
| :--------------- | :-------------------- | :------------------------------- |
| ✅ **FastAPI**    | ✅ **SQLAlchemy**      | ✅ **OAuth2** (GitHub, Google)    |
| ✅ **Litestar**   | ✅ **SQLModel**        | ✅ **TOTP 2FA** |
| ✅ **Django**     | ✅ **MongoDB (Motor)** | ✅ **Magic Links** (Passwordless) |
| ✅ **Flask**      | 🚧 Prisma *(Soon)*    | ✅ **Rate Limiting** |
| -                | -                     | ✅ **Passkeys / WebAuthn** |

### Roadmap (Beyond v1.0.0)

Now that the core ecosystem is stable, we are focusing on Developer Experience
(DX) and frontend integrations:

- [✅] Role-Based Access Control (RBAC) and Permissions Layer
- [✅] Flask Framework Adapter. 
- [✅] Implement WebAuthn / Passkeys Support
- [ ] Documentation and Examples
- [ ] Vanilla JS, React / Next.js SDK (Hooks and server-side utilities).
- [ ] A CLI tool to help with bootstrapping projects among other things
- [ ] Admin Dashboard Plugin (A UI to manage users, sessions, and anything related to authentication and authorization).
- [ ] More OAuth Providers (Apple, Microsoft, Discord).

### Contributing

We welcome contributions! Qulf uses a modern and fast development stack powered
by Rust-based tools.

 **WE WILL PUBLISH A CONTRIBUTING.md VERY SOON.** 

### Prerequisites

You only need to install mise-en-place. mise will automatically manage Python, 
uv, and all environment variables for you.

Dev Setup

1. Clone the repository:

```bash
  git clone https://github.com/qulflabs/qulf.git
```



```bash
  cd qulf
```

2. Set up the environment and install dependencies:

```bash
  mise run setup
```

3. Run tests (must maintain 100% coverage):

```bash
  mise run tests
```

To see all available development commands, simply type:

```bash
  mise tasks
```

### Optional: Zellij Development Workspace

If you use [Zellij](https://zellij.dev/), we includes a development layout to get you up and running immediately.

Launch the workspace with:

```bash
mise zellij
```
or
```bash
zellij --layout ./zlayout.kdl
```

The layout is designed around the typical Qulf development workflow and provides
multiple dedicated workspaces:

| Tab | Purpose |
| :-- | :------ |
| **core** | Main development workspace with multiple panes. |
| **tests** | Dedicated terminal for running the test suite continuously. |

The **core** tab is split into three working directories:

```
┌───────────────────────────────────────────────────────────┐
│                    Main Workspace                         │
├───────────────────────────┬───────────────────────────────┤
│                           │             web               │
│                           ├───────────────────────────────┤
│        Repository         │            demo               │
│                           │                               │
└───────────────────────────┴───────────────────────────────┘
```

- **Repository (left):** Primary development terminal for editing, Git, and running `mise` tasks.
- **web:** Documentation website (Fumadocs / Next.js).
- **demo:** Example application for manually testing new features.

The layout also includes:

- Persistent tab and status bars.
- Built-in tiled and floating layouts for additional panes.
- A dedicated **tests** tab for running `mise run tests`, `pytest`, or other long-running commands while you continue development in the main workspace.

Using this layout keeps documentation, examples, and the core library available at the same time without manually arranging panes every session.

### License

Distributed under the MIT License. See [LICENSE](https://github.com/qulflabs/qulf/blob/main/LICENSE) for more information.

***
