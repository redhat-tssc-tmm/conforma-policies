package sonarqube_quality_gate

import rego.v1

# METADATA
# title: SonarQube scan task executed
# description: >-
#   Per Parasol company policy, the build must include the
#   sonar-scan task in the pipeline.
# custom:
#   short_name: task_present
#   failure_msg: "Required task sonar-scan not found in attestation"
deny contains result if {
	every att in input.attestations {
		not _task_ran(att, "sonar-scan")
	}
	result := {"msg": "Required task 'sonar-scan' not found in attestation — task must run as part of the pipeline"}
}

# METADATA
# title: SonarQube quality gate passed
# description: >-
#   Per Parasol company policy, the image must pass the
#   SonarQube quality gate before promotion.
# custom:
#   short_name: quality_gate_passed
#   failure_msg: "SonarQube quality gate FAILED"
deny contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "sonar-scan"
	some r in task.results
	r.name == "SONAR_QUALITY_RESULT"
	qd := json.unmarshal(r.value)
	qd.qualityGateStatus != "OK"
	result := {"msg": sprintf("SonarQube quality gate FAILED (status: %s, project: %s, dashboard: %s)", [qd.qualityGateStatus, qd.projectKey, qd.dashboardUrl])}
}

# METADATA
# title: SonarQube analysis summary
# description: >-
#   Reports key SonarQube metrics from the quality gate analysis.
# custom:
#   short_name: analysis_summary
#   failure_msg: "SonarQube analysis summary"
warn contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "sonar-scan"
	some r in task.results
	r.name == "SONAR_QUALITY_RESULT"
	qd := json.unmarshal(r.value)
	metrics := qd.metrics
	result := {"msg": sprintf("SonarQube: Bugs: %s, Vulnerabilities: %s, Code Smells: %s, Coverage: %s%%, Duplications: %s%%, Security Hotspots: %s", [metrics.bugs, metrics.vulnerabilities, metrics.code_smells, metrics.coverage, metrics.duplicated_lines_density, metrics.security_hotspots])}
}

# METADATA
# title: SonarQube quality conditions met
# description: >-
#   Individual SonarQube quality conditions should pass.
# custom:
#   short_name: conditions_met
#   failure_msg: "SonarQube condition failed"
warn contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "sonar-scan"
	some r in task.results
	r.name == "SONAR_QUALITY_RESULT"
	qd := json.unmarshal(r.value)
	some condition in qd.conditions
	condition.status != "OK"
	result := {"msg": sprintf("SonarQube condition failed: %s (value: %s, threshold: %s)", [condition.metric, condition.value, condition.threshold])}
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
