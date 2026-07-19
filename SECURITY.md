# Security

## Reporting a vulnerability

Do **not** open a public issue. Report sensitive findings directly to the
repository maintainer via GitHub's "Report a vulnerability" flow or
private communication channel.

---

## Credential rotation — 2026-07-19

A `.env` file containing live credentials (Postgres password, API key)
was accidentally committed to this repository in its initial setup. This
file has been purged from all git history using `git filter-repo`, and
all credentials previously exposed in that file were rotated on
**2026-07-19**:

- PostgreSQL password → rotated
- API key (`AI_SCRAPER__API__API_KEY`) → rotated

### If you cloned this repository before 2026-07-19

Your local clone may still contain the old `.env` file with stale
credentials. **These credentials are dead and will not work.** Delete
your local `.env` and regenerate from `.env.example`:

```bash
rm .env
cp .env.example .env
# Edit .env with new values — do NOT reuse the old ones
```

### Preventative measures now in place

- `.env` is listed in `.gitignore`
- A CI check (`ci-secrets-check.yml`) fails the build if `.env` or any
  credential-pattern file is present in a PR diff
- `.env.example` contains only placeholder values — no real credentials
  are ever committed
- Tests are isolated from ambient `.env` state (they inject an explicit
  `AppConfig` via `set_config()` at session start rather than relying on
  whatever `.env` happens to be sitting on the developer's disk)
