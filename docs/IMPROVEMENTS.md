# Improvement backlog

Captured 2026-11-23. Priorities: **P1** correctness/security, **P2** capability,
**P3** polish. Keep the existing suite green and add tests for every change.

## P1

- **Strict typing.** `py.typed` exists; add a `[tool.mypy]` section with
  `strict = true` and a CI step. Definition of done: `mypy src` is clean.
- **Python 3.14 in CI.** Add `"3.14"` to the matrix.
- **Deterministic output.** `age_days` uses the current date, so JSON is not
  reproducible. Add `--now ISO8601` (default: current UTC) and thread it into
  ignore-expiry and age calculations. Test two runs with a fixed `--now` are
  byte-identical.
- **Policy self-test.** Add `cloudrift rules test --policy-dir DIR` so users
  authoring custom policies can run paired vulnerable/compliant fixtures. Reuse
  the data-driven harness already used for the bundled pack.

## P2

- **Changed-files mode.** `--changed-only --base origin/main` using `git diff
  --name-only`, so PRs scan only touched manifests.
- **JUnit output.** `--format junit` for CI test reporters.
- **GitHub Action wrapper.** Composite action with `fail-on`, `policy-dir` and
  automatic SARIF upload, plus a caller example.
- **Container and Compose scanning.** New input type for `Dockerfile` and
  `docker-compose.yml`: root user, `latest` tags, privileged mode, host network,
  secrets in environment, writable mounts.
- **PyPI release.** OIDC publishing and `pip install cloudrift` install lines.

## P3

- HTML report: policy description tooltips and a print stylesheet.
- `--jobs N` for large plans; benchmark 1,000+ resources in `docs/ARCHITECTURE.md`.
- Shell completions for `scan` and `rules`.
- Starter Azure and GCP policy packs (keep out of the default pack).
- Add `CODE_OF_CONDUCT.md`.
