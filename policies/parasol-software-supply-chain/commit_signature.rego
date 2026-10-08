package commit_signature

import rego.v1

# METADATA
# title: Commit signature verification task executed
# description: >-
#   Per Parasol company policy, the build must include the
#   verify-commit-signature task in the pipeline.
# custom:
#   short_name: task_present
#   failure_msg: "Required task verify-commit-signature not found in attestation"
deny contains result if {
	every att in input.attestations {
		not _task_ran(att, "verify-commit-signature")
	}
	result := {
		"msg": "Required task 'verify-commit-signature' not found in attestation — task must run as part of the pipeline",
		"metadata": {"code": "commit_signature.task_present"},
	}
}

# METADATA
# title: Commit must be signed by a developer
# description: >-
#   Per Parasol company policy, production releases require a
#   human-signed commit. Unsigned commits are rejected.
# custom:
#   short_name: commit_signed
#   failure_msg: "Commit is unsigned"
deny contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "verify-commit-signature"
	some r in task.results
	r.name == "SIGNATURE_STATUS"
	r.value == "UNSIGNED"
	result := {
		"msg": "Commit is unsigned — production releases require a signed commit",
		"metadata": {"code": "commit_signature.commit_signed"},
	}
}

# METADATA
# title: Bot commits cannot be promoted to production
# description: >-
#   Per Parasol company policy, automated bot commits are not
#   acceptable for production releases.
# custom:
#   short_name: no_bot_commit
#   failure_msg: "Automated bot commit cannot be promoted to production"
deny contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "verify-commit-signature"
	some r in task.results
	r.name == "SIGNATURE_STATUS"
	r.value == "BOT_COMMIT"
	result := {
		"msg": "Automated bot commit cannot be promoted to production — a human-signed commit is required",
		"metadata": {"code": "commit_signature.no_bot_commit"},
	}
}

# METADATA
# title: Commit signature verified
# description: >-
#   Reports the signer identity when the commit is properly signed.
# custom:
#   short_name: signer_info
#   failure_msg: "Commit signer information"
warn contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "verify-commit-signature"
	some r in task.results
	r.name == "SIGNATURE_STATUS"
	r.value == "SIGNED"
	some d in task.results
	d.name == "SIGNATURE_DETAILS"
	result := {
		"msg": sprintf("Signed by: %v", [d.value]),
		"metadata": {"code": "commit_signature.signer_info"},
	}
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
