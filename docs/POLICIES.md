# Policies

`cloudrift` ships 49 policies: 31 for AWS Terraform and 18 for Kubernetes. Every
policy is a YAML document with a declarative assertion. Assertions run in a
restricted expression evaluator that never calls Python `eval`.

- 8 critical, 19 high, 16 medium, 5 low, 1 informational.
- Policies are loaded from `src/cloudrift/policies/` and embedded in the wheel.
- `cloudrift rules list`, `rules show ID`, `rules validate`, and `explain ID`
  inspect the active pack.

## Bundled policies

### AWS (31)

| ID | Severity | Resource types | Title |
| --- | --- | --- | --- |
| CLDR-0001 | critical | `aws_s3_bucket` | S3 bucket ACL grants public access |
| CLDR-0002 | critical | `aws_s3_bucket_policy` | S3 bucket policy allows a public principal |
| CLDR-0003 | high | `aws_s3_bucket` | S3 bucket has no default encryption |
| CLDR-0004 | medium | `aws_s3_bucket` | S3 bucket versioning is disabled |
| CLDR-0005 | low | `aws_s3_bucket` | S3 bucket access logging is disabled |
| CLDR-0006 | high | `aws_security_group`, `aws_security_group_rule` | SSH is open to the internet |
| CLDR-0007 | high | `aws_security_group`, `aws_security_group_rule` | RDP is open to the internet |
| CLDR-0008 | high | `aws_security_group`, `aws_security_group_rule` | MySQL is open to the internet |
| CLDR-0009 | high | `aws_security_group`, `aws_security_group_rule` | PostgreSQL is open to the internet |
| CLDR-0010 | high | `aws_security_group`, `aws_security_group_rule` | Security group allows all ports from the internet |
| CLDR-0011 | high | `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy` | IAM policy allows wildcard actions |
| CLDR-0012 | medium | `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy` | IAM policy allows all resources |
| CLDR-0013 | critical | `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy` | IAM policy grants full administrative access |
| CLDR-0014 | critical | `aws_iam_access_key` | Root account access key is declared |
| CLDR-0015 | medium | `aws_iam_access_key` | IAM access key is older than 90 days |
| CLDR-0016 | critical | `aws_db_instance` | RDS instance is publicly accessible |
| CLDR-0017 | high | `aws_db_instance` | RDS storage is not encrypted |
| CLDR-0018 | medium | `aws_db_instance` | RDS automated backups are disabled |
| CLDR-0019 | low | `aws_db_instance` | RDS deletion protection is disabled |
| CLDR-0020 | high | `aws_ebs_volume` | EBS volume is unencrypted |
| CLDR-0021 | high | `aws_cloudtrail` | CloudTrail logging is disabled |
| CLDR-0022 | low | `aws_cloudtrail` | CloudTrail trail is not multi-region |
| CLDR-0023 | medium | `aws_kms_key` | KMS key rotation is disabled |
| CLDR-0024 | high | `aws_lb_listener`, `aws_alb_listener` | Load balancer listener uses HTTP |
| CLDR-0025 | high | `aws_lambda_function` | Lambda environment contains a secret-like value |
| CLDR-0026 | medium | `aws_vpc` | VPC has no flow logs |
| CLDR-0027 | medium | `aws_sqs_queue` | SQS queue is not encrypted |
| CLDR-0028 | medium | `aws_sns_topic` | SNS topic is not encrypted |
| CLDR-0029 | medium | `aws_ecr_repository` | ECR repository does not scan images on push |
| CLDR-0030 | medium | `aws_secretsmanager_secret` | Secrets Manager secret has no rotation |
| CLDR-0031 | critical | `aws_instance` | Public instance exposes SSH to the internet |

### Kubernetes (18)

| ID | Severity | Resource types | Title |
| --- | --- | --- | --- |
| CLDR-1001 | critical | Pod workloads | Container runs in privileged mode |
| CLDR-1002 | high | Pod workloads | Container allows privilege escalation |
| CLDR-1003 | medium | Pod workloads | Container may run as root |
| CLDR-1004 | high | Pod workloads | Container adds dangerous Linux capabilities |
| CLDR-1005 | high | Pod workloads | Pod mounts a hostPath volume |
| CLDR-1006 | high | Pod workloads | Pod shares a host namespace |
| CLDR-1007 | medium | Pod workloads | Container image uses a mutable tag |
| CLDR-1008 | medium | Pod workloads | Container has no CPU or memory limits |
| CLDR-1009 | low | All `kubernetes_*` resources | Resource uses the default namespace |
| CLDR-1010 | medium | Pod workloads, `kubernetes_service_account` | Service account token is auto-mounted |
| CLDR-1011 | high | `kubernetes_role`, `kubernetes_cluster_role` | RBAC role grants wildcard permissions |
| CLDR-1012 | critical | `kubernetes_cluster_role_binding`, `kubernetes_role_binding` | cluster-admin is bound to a non-system subject |
| CLDR-1013 | high | `kubernetes_secret` | Secret manifest contains literal data |
| CLDR-1014 | high | Pod workloads | Container environment contains a secret-like literal |
| CLDR-1015 | medium | Pod workloads | Container disables seccomp confinement |
| CLDR-1016 | low | Pod workloads | Container root filesystem is writable |
| CLDR-1017 | medium | Pod workloads | Namespace has no NetworkPolicy |
| CLDR-1018 | info | `kubernetes_service` | LoadBalancer Service has no internal annotation |

"Pod workloads" means Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet,
ReplicationController, Job, and CronJob. Container-level checks inspect regular,
init, and ephemeral containers.

## Policy schema

A policy file contains one mapping, a list of mappings, or a `policies` list.
Unknown keys are rejected so typos fail loudly.

```yaml
policies:
  - id: CLDR-0003
    title: S3 bucket has no default encryption
    description: >-
      The bucket does not define server-side encryption.
    severity: high
    provider: aws
    resource: aws_s3_bucket
    assert: exists(resource.server_side_encryption_configuration)
    message: S3 bucket {name} has no server-side encryption configuration.
    remediation: >-
      Add a server_side_encryption_configuration block using AES256 or
      aws:kms with a customer managed key.
    references:
      - https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
    tags: [s3, storage, encryption]
    location:
      - server_side_encryption_configuration
```

| Key | Required | Description |
| --- | --- | --- |
| `id` | yes | `CLDR-` followed by exactly four digits. Must be unique in a pack. |
| `title` | yes | Short one-line summary used in every report. |
| `description` | yes | Why the policy matters. |
| `severity` | yes | `critical`, `high`, `medium`, `low`, or `info`. |
| `provider` | yes | `aws` or `kubernetes`. |
| `resource` | yes | One or more resource type globs, for example `aws_s3_bucket` or `kubernetes_*`. |
| `assert` | yes | Expression that is true when the resource is compliant. |
| `message` | yes | Finding text. Supports the placeholders below. |
| `remediation` | yes | Actionable fix. Supports the same placeholders. |
| `references` | no | Documentation links copied into findings. |
| `tags` | no | Free-form labels for filtering and ownership. |
| `relations` | no | Related resources exposed as `related`. |
| `location` | no | Dotted key paths used to resolve a precise source line. |

Message placeholders are `{address}`, `{name}`, `{type}`, `{provider}`,
`{module}`, and `{namespace}`. Unknown placeholders are left untouched.

### Relations

`related` is a list of resource views selected by one or more relation specs.
Each spec supports:

```yaml
relations:
  - type: aws_flow_log       # required, list or scalar, globs allowed
    reference: true          # follow Terraform expression references
    via: [id]                # match source attribute values against target
    target: vpc_id            # candidate attribute that must equal a via value
    scope: namespace          # Kubernetes: same namespace
```

At least one of `reference`, `via`, or `scope` must be set. Resolution is
conservative and documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Expression language

Expressions use a Python-like syntax, but only a fixed, validated subset is
accepted. Roots are `resource`, `related`, and whitelisted function names.
Comprehension variables are scoped to their comprehension.

Supported syntax:

- Literals: strings, numbers, `True`, `False`, `None`, lists, tuples, sets,
  dictionaries.
- Attribute and subscript access, including slices: `resource.tags["env"]`.
- Arithmetic: `+`, `-`, `*`, `/`, `//`, `%`; unary `+`, `-`, `not`.
- Comparisons: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`, `is`,
  `is not`, including chained comparisons.
- Boolean `and`, `or`, and conditional expressions `a if condition else b`.
- List and generator comprehensions with up to four `for` clauses and `if`
  filters.
- Calls to whitelisted functions, with positional and named arguments.

Rejected on purpose: imports, lambdas, method calls, f-strings, walrus,
assignment expressions, `yield`, `await`, dunder attributes or keys, starred
arguments, dictionary unpacking, and any name outside the whitelist.

Limits: 500 AST nodes, depth 40, 100,000 evaluation steps, regular expressions
up to 500 characters, regex input up to 10,000 characters, JSON parsing up to
200,000 characters, and a 1,000,000-item sequence multiplication cap. Exceeding
a limit fails that policy for that resource and makes the CLI exit with code 2.

### Functions

| Function | Purpose |
| --- | --- |
| `len(value)` | Length of a string, collection, or mapping; 0 for `None`. |
| `any(value)` / `all(value)` | Truthiness over a collection; `all` is vacuously true for `None`. |
| `lower(value)` / `upper(value)` | String case conversion, safe for non-strings. |
| `contains(haystack, needle)` | Membership test for strings and collections. |
| `startswith(value, prefix)` / `endswith(value, suffix)` | String prefix and suffix tests. |
| `cidr_contains(container, candidate)` | True when an address or CIDR is inside another. |
| `is_public_cidr(value)` | True for internet-routable ranges such as `0.0.0.0/0` and `::/0`. |
| `exists(value)` / `missing(value)` | Null checks with clear intent. |
| `get(obj, key, default=None)` | Safe dotted-path lookup. |
| `to_int(value)` / `to_bool(value)` | Tolerant coercion; unknown values become `0` or `False`. |
| `regex_match(value, pattern)` | Bounded regular expression search. |
| `json_parse(value)` | Parse embedded JSON, returning `{}` on malformed input. |
| `keys(obj)` / `values(obj)` / `items(obj)` | Mapping projections. |
| `image_tag(image)` | Container tag, ignoring registry ports and digest prefixes. |
| `age_days(timestamp)` | Age of an ISO-8601 timestamp in days; 0 when unparsable. |
| `iam_actions(policy)` / `iam_resources(policy)` | Flattened actions and resources from an IAM policy document. |
| `iam_wildcard_action(policy)` | Allow statement contains a wildcard action. |
| `iam_wildcard_resource(policy)` | Allow statement targets every resource. |
| `iam_allow_all(policy)` | Allow `*` on `*`. |
| `iam_public_principal(policy)` | Unconditional Allow to `Principal: "*"`. |
| `sg_ingress_rules(resource)` | Normalized ingress rules for a security group or rule resource. |

All functions are pure. They never read files, environment variables, network
sockets, subprocesses, or clocks. `age_days` compares against the current UTC
date, which is the only ambient input.

## Writing and validating a pack

1. Copy an existing policy and change the ID, metadata, and assertion.
2. Put the file in a directory such as `policies/`.
3. Validate it:

   ```console
   $ cloudrift rules validate ./policies
   1 policies valid
   ```

4. Scan with it. `--policy-dir` replaces the bundled pack:

   ```console
   $ cloudrift scan plan.json --policy-dir ./policies
   ```

5. Add vulnerable and compliant fixtures to `tests/fixtures/policy_cases.yml`
   and run the test suite.

A new AWS policy should normally use IDs in the `CLDR-0xxx` range, and a new
Kubernetes policy in the `CLDR-1xxx` range. The loader only enforces the
`CLDR-####` shape, not the numeric block.

## Safe evaluator guarantees

The evaluator parses with `ast.parse(mode="eval")`, validates every node, and
then interprets the tree itself. It does not compile or execute Python code.
Subscript access rejects private keys, attribute access rejects names starting
with `_`, and call targets must be one of the functions above. Malicious inputs
are rejected at load time or fail only the current resource at evaluation time;
they cannot escape into the interpreter.
