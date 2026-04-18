# KICS-TF-AZURE-047
# Ported from: aks_uses_azure_policies_addon_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_aks_azure_policy_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-047",
	"name": "AKS Azure Policy addon disabled",
	"description": "Azure Kubernetes Service does not have the Azure Policy addon enabled. Azure Policy for AKS allows you to enforce organizational standards and assess compliance at-scale.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["azure", "kubernetes", "aks", "azure-policy", "governance"],
}

# Before azurerm 3.0: addon_profile.azure_policy
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "addon_profile")
	ap_blocks := tf.sub_blocks(block, "addon_profile")
	some ap in ap_blocks

	# azure_policy not defined in addon_profile
	not tf.has_sub_block(ap, "azure_policy")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 10)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' does not have Azure Policy addon configured. Add azure_policy block to addon_profile", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "addon_profile")
	ap_blocks := tf.sub_blocks(block, "addon_profile")
	some ap in ap_blocks

	tf.has_sub_block(ap, "azure_policy")
	ap_blocks2 := tf.sub_blocks(ap, "azure_policy")
	some ap2 in ap_blocks2

	# enabled is false
	enabled := tf.bool_attr(ap2, "enabled")
	enabled == false

	line_num := tf.line_number(content, ap2, "enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' has Azure Policy addon disabled", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# After azurerm 3.0: azure_policy_enabled
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	# azure_policy_enabled is false
	enabled := tf.bool_attr(block, "azure_policy_enabled")
	enabled == false

	line_num := tf.line_number(content, block, "azure_policy_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' has Azure Policy disabled (azure_policy_enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Missing any Azure Policy configuration
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	# Neither addon_profile.azure_policy nor azure_policy_enabled configured
	not tf.has_sub_block(block, "addon_profile")
	not tf.has_key(block, "azure_policy_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' does not have Azure Policy addon configured. Add azure_policy_enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
