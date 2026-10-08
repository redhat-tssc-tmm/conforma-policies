package acs_image_check

import rego.v1

# METADATA
# title: ACS image policy check task executed
# description: >-
#   Per Parasol company policy, the build must include the
#   acs-image-check task in the pipeline.
# custom:
#   short_name: acs_image_check_task_present
#   failure_msg: Required task 'acs-image-check' not found in attestation
deny contains result if {
	every att in input.attestations {
		not _task_ran(att, "acs-image-check")
	}
	result := {"msg": "Required task 'acs-image-check' not found in attestation — task must run as part of the pipeline"}
}

# METADATA
# title: ACS image policy check passed
# description: >-
#   Per Parasol company policy, the image must pass all ACS
#   security policy checks before promotion.
# custom:
#   short_name: acs_image_check_passed
#   failure_msg: "ACS image policy check did not pass: %s"
deny contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "acs-image-check"
	some r in task.results
	r.name == "CHECK_STATUS"
	r.value != "PASSED"
	result := {"msg": sprintf("ACS image policy check did not pass (status: %s)", [r.value])}
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
