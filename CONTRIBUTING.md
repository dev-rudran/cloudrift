# Contributing

Thanks for helping make `cloudrift` better. This project favors small, focused
changes with tests and clear documentation.

## Development setup

Python 3.10 or newer is required. Python 3.13 is the newest version exercised
in CI.

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python -m pip install --upgrade pip
$ python -m pip install -e ".[dev]"
$ pytest
```

The package uses a `src/` layout. Runtime dependencies are limited to PyYAML.
Development dependencies are declared in `pyproject.toml` under `dev`.

## Quality gates

Run the same checks as CI before sending a change:

```console
$ ruff check .
$ ruff format --check .
$ bandit -r src
$ pytest
```

`make check` runs all four. `make coverage` produces a terminal coverage report.

Please keep the suite deterministic. Tests must not require network access,
cloud credentials, or a Kubernetes cluster. Use `tmp_path` and fixtures rather
than writing into the repository.

## Adding or changing a policy

1. Pick an ID. AWS policies use the `CLDR-0xxx` block; Kubernetes policies use
   `CLDR-1xxx`. Add a new policy to the most relevant file in
   `src/cloudrift/policies/`.
2. Fill every required field. See [docs/POLICIES.md](docs/POLICIES.md) for the
   schema, the expression language, and the helper functions.
3. Write an assertion that is true for compliant resources. Prefer explicit
   guards such as `exists(value)` over assumptions about missing attributes.
4. Add a vulnerable and a compliant case to `tests/fixtures/policy_cases.yml`.
   The policy suite requires both directions for every rule.
5. If the policy needs another resource, use a `relations` spec. Do not add a
   general graph API or a method call to the expression language.
6. Run `cloudrift rules validate` and the full test suite.

Policy changes should explain the security impact in the description and give a
specific, actionable remediation. Avoid vendor-specific account IDs, region
names, or organization names in bundled rules.

## Changing the expression language

`src/cloudrift/policy/expr.py` is security-sensitive. Any new syntax must be
added to the validator, the evaluator, and the hostile-input tests. New
functions belong in `builtins.py`, must be pure, and must be safe for untrusted
input. Never introduce `eval`, `exec`, `compile`, imports, attribute traversal
into Python internals, filesystem access, environment access, network access, or
subprocesses.

Include tests that prove rejected syntax stays rejected. If you add a resource
limit, test the limit and its error message.

## Adding an input format

Start with a failing test in `tests/test_detect.py` and a fixture in
`tests/fixtures/`. Normalize into the existing `Resource` model instead of
adding provider-specific fields to the engine. Update `detect.py`, the relevant
loader, and the documentation. New formats should preserve a stable address and
a source location when the format provides one.

## Code style

- `ruff` handles linting and formatting; line length is 100.
- Type annotations are expected on public functions and on non-trivial internal
  code. The project targets Python 3.10, so use `from __future__ import
  annotations` for modern annotations in modules that need it.
- Keep CLI concerns in `cli.py`; library code should not print or exit.
- Expected user errors derive from `CloudriftError` and produce exit code 2.
- Escape untrusted text for the report format you are writing.
- No emojis in code, policy text, reports, or documentation.
- Do not add generated attribution or tool signatures to commits, files, or
  documentation.

## Documentation

Update the relevant document when behavior changes:

- `README.md` for user-facing commands and output.
- `docs/POLICIES.md` for the policy pack and expression language.
- `docs/ARCHITECTURE.md` for data flow, formats, and design decisions.
- `SECURITY.md` for the threat model and disclosure process.
- `CHANGELOG.md` for notable changes.

Console examples in the README must be real output from the current version.
Regenerate them after changing report rendering.

## Pull requests

Describe the problem, the approach, and the user-visible effect. Include the
commands you ran and their results. Keep unrelated refactors out of a bug fix or
a policy addition. If a change alters JSON or SARIF output, call out the schema
impact explicitly.

By contributing, you agree that your contribution is licensed under the MIT
License and that you have the right to submit it.
