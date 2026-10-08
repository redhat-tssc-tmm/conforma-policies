package acs_image_scan

import rego.v1

# METADATA
# title: ACS image scan task executed
# description: >-
#   Per Parasol company policy, the build must include the
#   acs-image-scan task in the pipeline.
# custom:
#   short_name: acs_image_scan_task_present
#   failure_msg: Required task 'acs-image-scan' not found in attestation
deny contains result if {
	every att in input.attestations {
		not _task_ran(att, "acs-image-scan")
	}
	result := {"msg": "Required task 'acs-image-scan' not found in attestation — task must run as part of the pipeline"}
}

# METADATA
# title: No critical vulnerabilities in image
# description: >-
#   Images with critical vulnerabilities should be reviewed
#   before production release.
# custom:
#   short_name: acs_image_scan_no_critical
#   failure_msg: "ACS image scan found critical vulnerabilities: %s"
warn contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "acs-image-scan"
	some r in task.results
	r.name == "SCAN_OUTPUT"
	scan := json.unmarshal(r.value)
	vulns := scan.vulnerabilities
	to_number(vulns.critical) > 0
	result := {"msg": sprintf("ACS image scan found %s critical vulnerabilities", [vulns.critical])}
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
