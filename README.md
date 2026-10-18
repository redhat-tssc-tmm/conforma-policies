# Conforma Policies

Central policy repository for the Secured Parasol Insurance pipeline.
Policies are referenced by the `ec-validate` Tekton task via `git::` URL.

## Structure

```
policies/
  <policy-name>/
    policy.yaml                # EC policy configuration (sources list)
    policy/release/            # custom Rego rules (EC's required directory layout)
      <rule>.rego
    data/                      # optional: rule data overrides
      rule_data.yml
```

EC (Enterprise Contract) requires Rego files under `policy/release/` within the
source directory. This matches the directory convention used by conftest, which
EC runs with the `policy` namespace. Rego files use bare package names
(e.g. `package acs_image_check`), not `package policy.release.*` -- the
`policy.release` namespace comes from the directory structure.

## Available Policies

| Policy | Description |
|---|---|
| `minimal-base-policy` | Baseline: built-in signature and attestation checks only (empty sources) |
| `parasol-software-supply-chain` | Full supply chain validation: ACS image checks, commit signatures, SonarQube quality gate, release approval |

## How Policies Are Referenced

The `ec-validate` Tekton task passes the `--policy` flag with a `git::` URL
pointing to the policy directory:

```bash
ec validate image --image <image>@<digest> \
  --policy "git::https://<gitlab>/parasol/conforma-policies.git//policies/parasol-software-supply-chain?ref=main"
```

EC clones the repo, navigates to the subdirectory (after `//`), reads
`policy.yaml`, and fetches the `sources[].policy[]` entries to load Rego rules.

The `sources[].policy[]` URL in `policy.yaml` must use a **slightly different
URL** than the `--policy` flag (e.g. omit `.git` from the repo name) to avoid
an EC v0.9.x caching bug where identical URLs trigger a broken symlink path.

## Placeholder Substitution

The `policy.yaml` contains a `{{ cluster_subdomain }}` placeholder that is
replaced with the actual cluster domain during deployment. The GitLab init
job handles this substitution when importing the repo to the cluster's GitLab
instance. The `main` branch must be unprotected before pushing the substituted
value and re-protected afterwards.

## Custom Rego Rules

Rules use `deny` for violations and `warn` for warnings:

```rego
package my_rule

import rego.v1

# METADATA
# title: Short rule title
# description: >-
#   What this rule checks and how to fix violations.
# custom:
#   short_name: rule_identifier
#   failure_msg: "Human-readable failure message"
deny contains result if {
    # rule logic using input.attestations, input.image, etc.
    result := {
        "code": "my_rule.rule_identifier",
        "msg": "Failure description",
    }
}
```

### Input available to rules

- `input.attestations` -- SLSA provenance attestations (each with `.statement.predicate.buildConfig.tasks`)
- `input.image.ref` -- image reference including digest

### Parasol Supply Chain Rules

| Rule | Type | What it checks |
|---|---|---|
| `acs_image_check` | deny | ACS image policy check task ran and passed |
| `acs_image_scan` | deny/warn | ACS scan task ran; warns on vulnerabilities found |
| `commit_signature` | deny | Commit signature verification task ran, commit is signed, not a bot commit |
| `release_approval` | deny | Signed release approval attestation is present and approved |
| `sonarqube` | deny/warn | SonarQube scan task ran and quality gate passed; warns on findings |

## Adding a New Policy

1. Create `policies/<policy-name>/`
2. Add Rego rules under `policies/<policy-name>/policy/release/` with bare package names
3. Add a `policy.yaml` with a `sources[].policy[]` entry pointing to the policy directory via `git::` URL
4. Push to the main branch -- the `ec-validate` task picks it up via the git URL
