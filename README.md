# Conforma Policies

Central policy repository for the Secured Parasol Insurance pipeline.
Policies are referenced directly by the `ec-validate` Tekton task via
`git::` URL — no local clone is needed.

## Structure

```
policies/
  <policy-name>/
    policy.yaml        # EC policy configuration (sources, rules, config)
    rules/             # optional: custom Rego rules
      <rule-name>/
        <rule-name>.rego
    data/              # optional: rule data (custom or overrides)
      rule_data.yml
```

Each subdirectory under `policies/` is a self-contained policy that can be
referenced individually:

```bash
ec validate image --image <image>@<digest> \
  --policy "git::https://<gitlab>/parasol/conforma-policies.git//policies/minimal-base-policy?ref=module2"
```

## Available Policies

| Policy | Description |
|---|---|
| `minimal-base-policy` | Baseline validation using the `@minimal` conforma rule collection |

## Policy Authoring

A `policy.yaml` can reference rule sources in three ways:

### 1. Upstream OCI bundles (curated rule collections)

```yaml
sources:
  - name: upstream-minimal
    policy:
      - oci::quay.io/conforma/release-policy:latest
    config:
      include:
        - "@minimal"
      exclude:
        - hermetic_build_task
```

Available collections: `@minimal`, `@slsa3`, `@redhat`, `@redhat_security`,
`@github`, `@policy_data`, `@redhat_maven`, `@redhat_rpms`, `@rhtap-multi-ci`.

### 2. Fully custom local rules (no upstream dependency)

```yaml
sources:
  - name: custom-rules
    policy:
      - file::rules/          # loads all .rego files recursively
    data:
      - file::data/           # loads rule_data.yml
    config:
      include:
        - "*"                  # include all rules found
```

### 3. Mixed (upstream + custom in the same policy)

```yaml
sources:
  - name: upstream-minimal
    policy:
      - oci::quay.io/conforma/release-policy:latest
    config:
      include:
        - "@minimal"
  - name: custom-checks
    policy:
      - file::rules/
    data:
      - file::data/
    config:
      include:
        - "*"
```

## Writing Custom Rego Rules

Each `.rego` file under `rules/` must have annotated `deny` rules:

```rego
# METADATA
# title: Allowed image registry
# description: >-
#   Verify the image comes from an allowed registry prefix.
#   Configure allowed prefixes in rule_data.allowed_registry_prefixes.
# custom:
#   short_name: image_from_allowed_registry
#   failure_msg: "Image %q is not from an allowed registry"
#   collections:
#     - minimal
#
package allowed_registry

import rego.v1

deny contains result if {
    ref := object.get(input, ["image", "ref"], "")
    ref != ""
    allowed := object.get(data, ["rule_data", "allowed_registry_prefixes"], [])
    count(allowed) > 0
    not _ref_allowed(ref, allowed)
    result := {
        "code": "image_from_allowed_registry",
        "msg": sprintf("Image %q is not from an allowed registry", [ref]),
    }
}

_ref_allowed(ref, allowed) if {
    some prefix in allowed
    startswith(ref, prefix)
}
```

### Required annotations (at the rule scope)

- `title` — short rule title
- `description` — what this rule checks and how to fix violations
- `custom.short_name` — machine-readable rule identifier
- `custom.failure_msg` — human-readable failure message (supports `%s` sprintf)

### Optional annotations

- `custom.collections` — list of collection names (for `@collection` include filters)
- `custom.effective_on` — RFC 3339 date; if in the future, violations become warnings
- `custom.depends_on` — list of rules that must pass first

### Input object available to rules

When validating an image, rules receive:

- `input.image.ref` — image reference (always includes digest)
- `input.image.config` — OCI image config (`.Labels`, `.Env`, `.Cmd`, etc.)
- `input.image.signatures` — signature descriptors
- `input.image.source.git.url` / `.revision` — source git info
- `input.attestations` — SLSA provenance attestations

### Rule data

Custom rule data in `data/rule_data.yml` is available as `data.rule_data.*`
in Rego rules. Example:

```yaml
# data/rule_data.yml
allowed_registry_prefixes:
  - quay.io/
  - registry.redhat.io/
  - registry.access.redhat.com/
```

## Adding a New Policy

1. Create a new directory under `policies/`
2. Add a `policy.yaml` with your source configuration (upstream, custom, or mixed)
3. For custom rules, add `.rego` files under `rules/` with proper annotations
4. Optionally add a `data/` subdirectory with rule data
5. Push to `module2` branch — pipelines pick it up automatically via the git URL
