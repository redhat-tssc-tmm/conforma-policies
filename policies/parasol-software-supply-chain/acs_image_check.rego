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
# title: ACS image policy check passed
# description: Per Parasol company policy, the image must pass all ACS security policy checks
deny contains msg if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "acs-image-check"
	some result in task.results
	result.name == "CHECK_STATUS"
	result.value != "PASSED"
	msg := sprintf("ACS image policy check did not pass (status: %s)", [result.value])
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
