# ACCESS Account Backend

FastAPI service for creating and modifying ACCESS accounts.

## Running Python / tests

The workspace runs in a sandbox tied to the editor session: closing and
reopening the editor resets the sandbox, which can wipe the in-repo `.venv` and
any managed Python interpreters mid-session. **Do not rely on the in-repo
`.venv`.** Instead, always run Python by building a fresh `uv` environment in
`/tmp`:

```bash
cd ACCESS_Account_Backend
uv python install 3.13
UV_PROJECT_ENVIRONMENT=/tmp/aab-venv uv sync --dev
/tmp/aab-venv/bin/python -m pytest
```

If `/tmp/aab-venv` has been reclaimed (e.g. after a sandbox reset), just re-run
the `uv python install` + `uv sync` steps to recreate it. Do the install, sync,
and run within one shell invocation when possible so the interpreter and env
aren't reclaimed between steps.

The project pins Python 3.13 (`.python-version`); `uv`'s managed downloads
default to "manual", so `uv python install 3.13` is required before `uv sync`.

## Tests

- Suite lives in `tests/` (unit / clients / api), config in `pyproject.toml`.
- `tests/conftest.py` sets `APP_CONFIG` to `tests/.env` (dummy values) before any
  app import, so tests never read the real secrets `.env` symlink and make no
  real network/AWS calls.
- CI runs the same flow in `.github/workflows/tests.yml`.
