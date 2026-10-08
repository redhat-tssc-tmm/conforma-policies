package sonarqube_quality_gate

import rego.v1

# METADATA
# title: SonarQube scan task executed
# description: Per Parasol company policy, the build must include the sonar-scan task
deny contains msg if {
	every att in input.attestations {
		not _task_ran(att, "sonar-scan")
	}
	msg := "Required task 'sonar-scan' not found in attestation — task must run as part of the pipeline"
}

# METADATA
# title: SonarQube quality gate result present
# description: Per Parasol company policy, the build must produce a SonarQube quality gate result
deny contains msg if {
	every att in input.attestations {
		not _has_result(att.statement.predicate.buildConfig.results, "SONAR_QUALITY_RESULT")
	}
	msg := "SonarQube quality gate result not found in attestation"
}

# METADATA
# title: SonarQube quality gate passed
# description: Per Parasol company policy, the image must pass the SonarQube quality gate
deny contains msg if {
	some att in input.attestations
	some result in att.statement.predicate.buildConfig.results
	result.name == "SONAR_QUALITY_RESULT"
	qd := json.unmarshal(result.value)
	qd.qualityGateStatus != "OK"
	msg := sprintf("SonarQube quality gate FAILED (status: %s, project: %s, dashboard: %s)", [qd.qualityGateStatus, qd.projectKey, qd.dashboardUrl])
}

# METADATA
# title: SonarQube quality conditions met
# description: Individual SonarQube quality conditions should pass
warn contains msg if {
	some att in input.attestations
	some result in att.statement.predicate.buildConfig.results
	result.name == "SONAR_QUALITY_RESULT"
	qd := json.unmarshal(result.value)
	some condition in qd.conditions
	condition.status != "OK"
	msg := sprintf("SonarQube condition failed: %s (value: %s, threshold: %s)", [condition.metric, condition.value, condition.threshold])
}

_task_ran(att, name) if {
	some task in att.statement.predicate.buildConfig.tasks
	task.name == name
}

_has_result(results, name) if {
	some result in results
	result.name == name
}
