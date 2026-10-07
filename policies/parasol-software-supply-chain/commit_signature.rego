package commit_signature

import rego.v1

deny contains msg if {
	every att in input.attestations {
		not _task_ran(att, "verify-commit-signature")
	}
	msg := "Required task 'verify-commit-signature' not found in attestation — task must run as part of the pipeline"
}

deny contains msg if {
	every att in input.attestations {
		not _has_result(att.statement.predicate.buildConfig.results, "COMMIT_SIGNATURE_STATUS")
	}
	msg := "Commit signature status result not found in attestation"
}

deny contains msg if {
	some att in input.attestations
	some result in att.statement.predicate.buildConfig.results
	result.name == "COMMIT_SIGNATURE_STATUS"
	result.value == "UNSIGNED"
	msg := "Commit is unsigned — production releases require a signed commit"
}

deny contains msg if {
	some att in input.attestations
	some result in att.statement.predicate.buildConfig.results
	result.name == "COMMIT_SIGNATURE_STATUS"
	result.value == "BOT_COMMIT"
	msg := "Automated bot commit cannot be promoted to production — a human-signed commit is required"
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}

_has_result(results, name) if {
	some result in results
	result.name == name
}
