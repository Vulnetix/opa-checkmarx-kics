# Ported from checkmarx-kics: aks_private_cluster_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_azure_aks_02

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AZURE-AKS-02",
	"name": "AKS Private Cluster should be enabled",
	"description": "Azure Kubernetes Service (AKS) clusters should have private_cluster_enabled set to true. This ensures the Kubernetes API server endpoint has a private IP address.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "aks", "kubernetes", "private", "security"],
}

findings contains finding if {
	some r in tf.resources("azurerm_kubernetes_cluster")
	not tf.has_key(r.block, "private_cluster_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("azurerm_kubernetes_cluster %q is missing private_cluster_enabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

findings contains finding if {
	some r in tf.resources("azurerm_kubernetes_cluster")
	tf.bool_attr(r.block, "private_cluster_enabled") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("azurerm_kubernetes_cluster %q has private_cluster_enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
