# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/stackdriver_logging_disabled

package vulnetix.rules.kics_tf_gcp_gke_logging_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-016",
	"name": "GKE cluster Stackdriver logging is disabled",
	"description": "GKE clusters should have Stackdriver logging enabled for security monitoring and audit purposes.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	val := terraform.string_attr(r.block, "logging_service")
	val == "none"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has Stackdriver logging disabled (logging_service = 'none')", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	val := terraform.string_attr(r.block, "logging_service")
	val == "logging.googleapis.com"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q uses legacy Stackdriver logging (logging.googleapis.com instead of logging.googleapis.com/kubernetes)", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
