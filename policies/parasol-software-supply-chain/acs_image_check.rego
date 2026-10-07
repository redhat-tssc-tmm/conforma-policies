package acs_image_check

import rego.v1

deny contains msg if {
	every att in input.attestations {
		not _task_ran(att, "acs-image-check")
	}
	msg := "Required task 'acs-image-check' not found in attestation — task must run as part of the pipeline"
}

deny contains msg if {
	every att in input.attestations {
		not _has_result(att.statement.predicate.buildConfig.results, "ACS_IMAGE_CHECK_STATUS")
	}
	msg := "ACS image policy check result not found in attestation"
}

deny contains msg if {
	some att in input.attestations
	some result in att.statement.predicate.buildConfig.results
	result.name == "ACS_IMAGE_CHECK_STATUS"
	result.value != "Succeeded"
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
