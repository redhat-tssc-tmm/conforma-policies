package acs_image_scan

import rego.v1

# METADATA
# title: ACS image scan task executed
# description: Per Parasol company policy, the build must include the acs-image-scan task
deny contains msg if {
	every att in input.attestations {
		not _task_ran(att, "acs-image-scan")
	}
	msg := "Required task 'acs-image-scan' not found in attestation — task must run as part of the pipeline"
}

# METADATA
# title: No critical vulnerabilities in image
# description: Images with critical vulnerabilities should be reviewed before production release
warn contains msg if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "acs-image-scan"
	some result in task.results
	result.name == "SCAN_OUTPUT"
	scan := json.unmarshal(result.value)
	vulns := scan.vulnerabilities
	to_number(vulns.critical) > 0
	msg := sprintf("ACS image scan found %s critical vulnerabilities", [vulns.critical])
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
