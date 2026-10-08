package policy.release.commit_signature

import rego.v1

# METADATA
# title: Commit signature verification task executed
# description: >-
#   Per Parasol company policy, the build must include the
#   verify-commit-signature task in the pipeline.
# custom:
#   short_name: commit_signature_task_present
#   failure_msg: Required task 'verify-commit-signature' not found in attestation
deny contains result if {
	every att in input.attestations {
		not _task_ran(att, "verify-commit-signature")
	}
	result := {"msg": "Required task 'verify-commit-signature' not found in attestation — task must run as part of the pipeline"}
}

# METADATA
# title: Commit must be signed by a developer
# description: >-
#   Per Parasol company policy, production releases require a
#   human-signed commit. Unsigned commits are rejected.
# custom:
#   short_name: commit_signature_signed
#   failure_msg: "Commit is unsigned — production releases require a signed commit"
deny contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "verify-commit-signature"
	some r in task.results
	r.name == "SIGNATURE_STATUS"
	r.value == "UNSIGNED"
	result := {"msg": "Commit is unsigned — production releases require a signed commit"}
}

# METADATA
# title: Bot commits cannot be promoted to production
# description: >-
#   Per Parasol company policy, automated bot commits are not
#   acceptable for production releases. A human-signed commit is required.
# custom:
#   short_name: commit_signature_no_bot
#   failure_msg: "Automated bot commit cannot be promoted to production"
deny contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "verify-commit-signature"
	some r in task.results
	r.name == "SIGNATURE_STATUS"
	r.value == "BOT_COMMIT"
	result := {"msg": "Automated bot commit cannot be promoted to production — a human-signed commit is required"}
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
