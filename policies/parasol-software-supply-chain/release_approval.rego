package release_approval

import rego.v1

_release_attestations contains att if {
	some att in input.attestations
	att.statement.predicateType == "https://parasol-insurance.com/releases/v1"
}

_latest_release := latest if {
	count(_release_attestations) > 0
	latest := [att |
		some att in _release_attestations
		att.statement.predicate.release.decisionDate
	][count([att |
		some att in _release_attestations
		att.statement.predicate.release.decisionDate
	]) - 1]
}

_sorted_by_date contains {
	"date": att.statement.predicate.release.decisionDate,
	"approved": att.statement.predicate.release.approved,
	"approver": att.statement.predicate.release.approver,
	"reason_b64": att.statement.predicate.documentation[0].reason,
} if {
	some att in _release_attestations
}

_latest if {
	count(_sorted_by_date) > 0
}

_newest_decision := decision if {
	all_dates := {d | some e in _sorted_by_date; d := e.date}
	max_date := max(all_dates)
	some e in _sorted_by_date
	e.date == max_date
	decision := e
}

# METADATA
# title: Parasol Signed Approval present
# description: >-
#   Per Parasol company policy, a signed release approval attestation
#   must be present on the image before promotion.
# custom:
#   short_name: approval_present
#   failure_msg: "No release approval attestation found"
deny contains result if {
	count(_release_attestations) == 0
	result := {
		"msg": "No release approval attestation found — image must be approved via the Parasol approval process",
		"code": "release_approval.approval_present",
	}
}

# METADATA
# title: Parasol Release Approved
# description: >-
#   Per Parasol company policy, the latest release approval
#   must indicate approval. Rejected releases cannot be promoted.
# custom:
#   short_name: release_approved
#   failure_msg: "Release was rejected"
deny contains result if {
	decision := _newest_decision
	decision.approved == false
	reason_decoded := base64.decode(decision.reason_b64)
	reason_short := substring(reason_decoded, 0, 50)
	result := {
		"msg": sprintf("Release rejected by %v — reason: %v", [decision.approver, reason_short]),
		"code": "release_approval.release_approved",
	}
}
