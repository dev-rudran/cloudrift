# Five-minute quickstart

## 1. Install

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e .
```

## 2. Scan the vulnerable examples

```console
$ cloudrift scan examples/vulnerable
Summary  51 findings (critical 8, high 19, medium 16, low 7, info 1)
Result   FAIL (gate: high)
```

The examples cover Terraform plan JSON and multi-document Kubernetes YAML, so
you can see both providers without a cloud account.

## 3. Scan a compliant stack

```console
$ cloudrift scan examples/compliant
No findings.
Result   PASS (gate: high)
```

## 4. Terraform plan input

```console
$ terraform show -json tfplan > plan.json
$ cloudrift scan plan.json --fail-on high
```

Raw HCL is intentionally not parsed; serialize the plan first.

## 5. Reports and CI

```console
$ cloudrift scan examples/vulnerable --format sarif -o cloudrift.sarif
$ cloudrift scan examples/vulnerable --format html -o cloudrift.html
$ cloudrift scan examples/vulnerable --baseline accepted.json
```

Add your own rules with `--policy-dir ./policies`; see `docs/POLICIES.md` for the
expression language and its security model.
