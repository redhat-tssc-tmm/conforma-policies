package acs_image_scan

import rego.v1

# METADATA
# title: ACS image scan task executed
# description: >-
#   Per Parasol company policy, the build must include the
#   acs-image-scan task in the pipeline.
# custom:
#   short_name: task_present
#   failure_msg: "Required task acs-image-scan not found in attestation"
deny contains result if {
	every att in input.attestations {
		not _task_ran(att, "acs-image-scan")
	}
	result := {"msg": "Required task 'acs-image-scan' not found in attestation — task must run as part of the pipeline"}
}

# METADATA
# title: Image vulnerability summary
# description: >-
#   Reports vulnerability counts by severity from the ACS image scan.
# custom:
#   short_name: vulnerability_summary
#   failure_msg: "Vulnerabilities detected in image"
warn contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "acs-image-scan"
	some r in task.results
	r.name == "SCAN_OUTPUT"
	scan := json.unmarshal(r.value)
	vulns := scan.vulnerabilities
	total := to_number(vulns.critical) + to_number(vulns.high) + to_number(vulns.medium) + to_number(vulns.low)
	total > 0
	result := {"msg": sprintf("Vulnerabilities found — Critical: %s, High: %s, Medium: %s, Low: %s", [vulns.critical, vulns.high, vulns.medium, vulns.low])}
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
