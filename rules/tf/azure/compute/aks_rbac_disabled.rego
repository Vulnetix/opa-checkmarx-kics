# KICS-TF-AZURE-004
# Ported from: aks_rbac_disabled
# Severity: High

package vulnetix.rules.kics_tf_azure_aks_rbac_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-004",
	"name": "AKS RBAC disabled",
	"description": "Azure Kubernetes Service cluster does not have Role-Based Access Control (RBAC) enabled. This allows any user with access to the cluster to perform any action, violating the principle of least privilege.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "kubernetes", "aks", "rbac", "access-control"],
}

# Check for azurerm < 3.0 style: role_based_access_control.enabled
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	# Has role_based_access_control block
	tf.has_sub_block(block, "role_based_access_control")
	rbac_block := tf.sub_blocks(block, "role_based_access_control")[0]

	# Check if enabled is set to false
	enabled := tf.bool_attr(rbac_block, "enabled")
	enabled == false

	line_num := tf.line_number(content, rbac_block, "enabled")
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' has RBAC disabled via role_based_access_control.enabled = false", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Check for azurerm >= 3.0 style: role_based_access_control_enabled
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	# role_based_access_control_enabled explicitly set to false
	enabled := tf.bool_attr(block, "role_based_access_control_enabled")
	enabled == false

	line_num := tf.line_number(content, block, "role_based_access_control_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' has role_based_access_control_enabled = false", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Check when role_based_access_control_enabled is not set (defaults to true in newer versions, but flag for clarity)
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	# Neither RBAC style is explicitly configured
	not tf.has_key(block, "role_based_access_control_enabled")
	not tf.has_sub_block(block, "role_based_access_control")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' does not explicitly enable RBAC. Add role_based_access_control_enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
