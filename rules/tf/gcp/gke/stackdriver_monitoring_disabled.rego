# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/stackdriver_monitoring_disabled

package vulnetix.rules.kics_tf_gcp_gke_monitoring_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-017",
	"name": "GKE cluster Stackdriver monitoring is disabled",
	"description": "GKE clusters should have Stackdriver monitoring enabled for observability and alerting.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "monitoring"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	val := terraform.string_attr(r.block, "monitoring_service")
	val == "none"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has Stackdriver monitoring disabled (monitoring_service = 'none')", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	val := terraform.string_attr(r.block, "monitoring_service")
	val == "monitoring.googleapis.com"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q uses legacy Stackdriver monitoring (monitoring.googleapis.com instead of monitoring.googleapis.com/kubernetes)", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
