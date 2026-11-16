# Security policy

## Supported versions

`cloudrift` is pre-1.0. Security fixes are issued on the latest `0.1.x`
release. Older prereleases are not maintained.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Report suspected vulnerabilities privately to
**rudraking2404@gmail.com**. Do not open a public issue for a security problem.

Include, when possible:

- The `cloudrift` version, Python version, and operating system.
- The input that triggers the issue. Redact secrets and account identifiers.
- The command line, expected behavior, and observed behavior.
- A minimal policy file if the issue involves the expression evaluator.
- Whether the issue can be triggered by an untrusted repository, pull request,
  or CI artifact.

You can expect an acknowledgement within 72 hours and an initial assessment
within 7 days. Please allow time for a fix and coordinated disclosure before
publishing details. Credit is offered unless you prefer to remain anonymous.

## Scope

Reports are especially relevant when they involve:

- Escaping the policy expression sandbox, including arbitrary code execution,
  filesystem access, environment access, network access, or subprocesses.
- Loading Python objects through YAML or JSON.
- Denial of service through pathologically large or deeply nested inputs,
  regular expressions, comprehensions, or sequence multiplication.
- Terminal escape injection or report injection through resource names,
  messages, file names, or policy fields.
- Path traversal or unexpected file reads outside explicitly supplied scan
  targets.
- Credential leakage in reports, logs, baselines, or error messages.

The following are generally out of scope:

- A policy producing a false positive or false negative for a valid input.
  Report those as regular bugs with the policy ID and a reproduction.
- Findings about the insecure example files under `examples/`; they are
  deliberately vulnerable.
- Vulnerabilities in Terraform, Kubernetes, PyYAML, or the operating system
  that do not involve `cloudrift` behavior. Report those upstream.
- Missing hardening that requires the attacker to already control the scanner
  process, its Python environment, or its policy pack.

## Design assumptions

- Inputs are untrusted. Policies are trusted configuration, but they are still
  validated and evaluated in a restricted interpreter.
- The scanner is not a sandbox for running arbitrary third-party code. Anyone
  who can replace the installed package or the Python environment can execute
  code; that is outside the policy language boundary.
- Cloudrift does not call cloud APIs and does not need credentials. It reads
  files the caller can already read.
- Reports can contain resource names, file paths, and policy messages. Treat
  them as potentially sensitive and apply the same access controls as the
  source infrastructure.

## Safe expression evaluator

Policy assertions are parsed with `ast.parse(mode="eval")` and interpreted by a
validator and evaluator in `src/cloudrift/policy/expr.py`. The evaluator:

- Rejects imports, lambdas, method calls, f-strings, walrus expressions,
  assignment, `yield`, `await`, starred arguments, dictionary unpacking, and
  private or dunder attributes and keys.
- Restricts names to `resource`, `related`, comprehension variables, and pure
  helper functions.
- Enforces limits on AST size, nesting depth, evaluation steps, regex length,
  regex input, JSON payload size, and sequence multiplication.
- Never calls `eval`, `exec`, or `compile` on policy text.

Policy loading rejects unknown YAML keys, invalid IDs, unsupported providers,
empty assertions, and malformed relation specs. A broken policy fails closed:
the CLI exits 2 rather than reporting a clean scan.

## Handling results

SARIF, JSON, and Markdown reports may include infrastructure details. Store
them with the same sensitivity as Terraform state and Kubernetes manifests.
Baselines contain policy IDs, resource addresses, file names, timestamps, and
finding metadata such as title, severity, and line, but not resource attribute
values.
