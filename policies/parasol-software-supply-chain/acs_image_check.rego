package acs_image_check

import rego.v1

# METADATA
# title: ACS image policy check task executed
# description: Per Parasol company policy, the build must include the acs-image-check task
deny contains msg if {
	every att in input.attestations {
		not _task_ran(att, "acs-image-check")
	}
	msg := "Required task 'acs-image-check' not found in attestation — task must run as part of the pipeline"
}

# METADATA
# title: ACS image policy check result present
# description: Per Parasol company policy, the build must produce an ACS policy check result
deny contains msg if {
	every att in input.attestations {
		not _has_result(att.statement.predicate.buildConfig.results, "ACS_IMAGE_CHECK_STATUS")
	}
	msg := "ACS image policy check result not found in attestation"
}

# METADATA
# title: ACS image policy check passed
# description: Per Parasol company policy, the image must pass all ACS security policy checks
deny contains msg if {
	some att in input.attestations
	some result in att.statement.predicate.buildConfig.results
	result.name == "ACS_IMAGE_CHECK_STATUS"
	result.value != "PASSED"
	msg := sprintf("ACS image policy check did not pass (status: %s)", [result.value])
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}

_has_result(results, name) if {
	some result in results
	result.name == name
}
