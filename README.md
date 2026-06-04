# 🛡️ Qulf

<p align="center">
  <em>The comprehensive, framework-agnostic, and heavily typed authentication library for Python.</em><br/>
  <em>Inspired by <a href="https://better-auth.com" target="_blank">Better-Auth</a>.</em>
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