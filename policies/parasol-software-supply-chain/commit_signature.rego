package commit_signature

import rego.v1

# METADATA
# title: Commit signature verification task executed
# description: Per Parasol company policy, the build must include the verify-commit-signature task
deny contains msg if {
	every att in input.attestations {
		not _task_ran(att, "verify-commit-signature")
	}
	msg := "Required task 'verify-commit-signature' not found in attestation — task must run as part of the pipeline"
}

# METADATA
# title: Commit must be signed by a developer
# description: Per Parasol company policy, production releases require a human-signed commit
deny contains msg if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "verify-commit-signature"
	some result in task.results
	result.name == "SIGNATURE_STATUS"
	result.value == "UNSIGNED"
	msg := "Commit is unsigned — production releases require a signed commit"
}

# METADATA
# title: Bot commits cannot be promoted to production
# description: Per Parasol company policy, automated bot commits are not acceptable for production releases
deny contains msg if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "verify-commit-signature"
	some result in task.results
	result.name == "SIGNATURE_STATUS"
	result.value == "BOT_COMMIT"
	msg := "Automated bot commit cannot be promoted to production — a human-signed commit is required"
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
