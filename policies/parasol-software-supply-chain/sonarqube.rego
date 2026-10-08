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
	result := {
		"msg": "Required task 'sonar-scan' not found in attestation — task must run as part of the pipeline",
		"metadata": {"code": "sonarqube_quality_gate.task_present"},
	}
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
	result := {
		"msg": sprintf("SonarQube quality gate FAILED (status: %v, dashboard: %v)", [qd.qualityGateStatus, qd.dashboardUrl]),
		"metadata": {"code": "sonarqube_quality_gate.quality_gate_passed"},
	}
}

# METADATA
# title: SonarQube analysis highlights
# description: >-
#   Reports noteworthy SonarQube findings (security hotspots,
#   bugs, vulnerabilities, or code smells).
# custom:
#   short_name: analysis_highlights
#   failure_msg: "SonarQube findings"
warn contains result if {
	some att in input.attestations
	some task in att.statement.predicate.buildConfig.tasks
	task.name == "sonar-scan"
	some r in task.results
	r.name == "SONAR_QUALITY_RESULT"
	qd := json.unmarshal(r.value)
	metrics := qd.metrics
	notable := to_number(metrics.bugs) + to_number(metrics.vulnerabilities) + to_number(metrics.code_smells) + to_number(metrics.security_hotspots)
	notable > 0
	result := {
		"msg": sprintf("SonarQube: Bugs: %v, Vulnerabilities: %v, Code Smells: %v, Security Hotspots: %v, Coverage: %v%% (report: %v)", [metrics.bugs, metrics.vulnerabilities, metrics.code_smells, metrics.security_hotspots, metrics.coverage, qd.dashboardUrl]),
		"metadata": {"code": "sonarqube_quality_gate.analysis_highlights"},
	}
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
	result := {
		"msg": sprintf("SonarQube condition failed: %v (value: %v, threshold: %v)", [condition.metric, condition.value, condition.threshold]),
		"metadata": {"code": "sonarqube_quality_gate.conditions_met"},
	}
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}
