# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Self-contained HTML report format with inline CSS and JavaScript, severity
  filters, free-text search, severity grouping, summary cards, and escaped
  finding content. `--format html` writes it, and a `.html` output path selects
  it automatically.

## [0.1.0] - 2026-11-15

### Added

- Terraform plan and state JSON ingestion, including modules, planned values,
  replacements, delete-only filtering, and configuration references.
- Multi-document Kubernetes YAML ingestion with `List` support, namespace
  handling, workload extraction, and source line tracking.
- 49 bundled policies: 31 AWS and 18 Kubernetes, with vulnerable and compliant
  fixtures for every rule.
- Safe policy expression language with an AST whitelist, step and size limits,
  pure helper functions, and comprehension support.
- Explicit cross-resource relations by Terraform reference, attribute matching,
  and Kubernetes namespace scope.
- Console, JSON, Markdown, and SARIF 2.1.0 reports.
- Severity filtering, configurable failure thresholds, and stable exit codes.
- Expiring ignore rules in `cloudrift.yaml` and repeatable `--ignore` globs.
- Baseline creation and drift comparison with new, existing, and fixed findings.
- CLI commands: `scan`, `rules list`, `rules show`, `rules validate`, `explain`,
  and `version`.
- Custom policy packs through `--policy-dir`.
- Example vulnerable and compliant Terraform and Kubernetes inputs.
- Documentation for policies, architecture, security, and contribution
  workflow, plus a CI matrix for Python 3.10 through 3.13.

[0.1.0]: https://github.com/dev-rudran/cloudrift/releases/tag/v0.1.0
