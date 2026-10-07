package acs_image_scan

import rego.v1

deny contains msg if {
	every att in input.attestations {
		not _task_ran(att, "acs-image-scan")
	}
	msg := "Required task 'acs-image-scan' not found in attestation — task must run as part of the pipeline"
}

deny contains msg if {
	every att in input.attestations {
		not _has_result(att.statement.predicate.buildConfig.results, "ACS_IMAGE_SCAN_OUTPUT")
	}
	msg := "ACS image scan results not found in attestation"
}

warn contains msg if {
	some att in input.attestations
	some result in att.statement.predicate.buildConfig.results
	result.name == "ACS_IMAGE_SCAN_OUTPUT"
	scan := json.unmarshal(result.value)
	vulns := scan.vulnerabilities
	to_number(vulns.critical) > 0
	msg := sprintf("ACS image scan found %s critical vulnerabilities", [vulns.critical])
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}

_has_result(results, name) if {
	some result in results
	result.name == name
}
