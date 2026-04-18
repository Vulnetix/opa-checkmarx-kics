# Ported from checkmarx-kics: aks_rbac_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_azure_aks_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AZURE-AKS-01",
	"name": "AKS RBAC should be enabled",
	"description": "Azure Kubernetes Service (AKS) clusters should have Role-Based Access Control (RBAC) enabled. RBAC allows fine-grained access control to Kubernetes resources.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "aks", "kubernetes", "rbac", "security"],
}

# Check for role_based_access_control.enabled (azurerm < 3.0)
findings contains finding if {
	some r in tf.resources("azurerm_kubernetes_cluster")
	tf.has_sub_block(r.block, "role_based_access_control")
	not regex.match(`(?s)role_based_access_control(?i)\s*\{[^\}]*enabled(?i)\s*=\s*true`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("azurerm_kubernetes_cluster %q has role_based_access_control.enabled != true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}

# Check for role_based_access_control_enabled (azurerm >= 3.0)
findings contains finding if {
	some r in tf.resources("azurerm_kubernetes_cluster")
	tf.bool_attr(r.block, "role_based_access_control_enabled") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("azurerm_kubernetes_cluster %q has role_based_access_control_enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

# Missing RBAC configuration entirely
findings contains finding if {
	some r in tf.resources("azurerm_kubernetes_cluster")
	not tf.has_key(r.block, "role_based_access_control_enabled")
	not tf.has_sub_block(r.block, "role_based_access_control")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("azurerm_kubernetes_cluster %q is missing RBAC configuration.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}
