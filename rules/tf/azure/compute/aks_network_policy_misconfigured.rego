# KICS-TF-AZURE-011
# Ported from: aks_network_policy_misconfigured
# Severity: Medium

package vulnetix.rules.kics_tf_azure_aks_network_policy_misconfigured

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-011",
	"name": "AKS network policy misconfigured",
	"description": "Azure Kubernetes Service cluster does not have a valid network policy configured. Without proper network policies, pods can communicate freely, violating network segmentation principles.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["azure", "kubernetes", "aks", "network-policy", "network-segmentation"],
}

valid_policies := {"azure", "calico"}

# Missing network_profile
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	not tf.has_sub_block(block, "network_profile")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' does not have network_profile configured. Add network_profile with network_policy", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Missing network_policy in network_profile
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "network_profile")
	np_blocks := tf.sub_blocks(block, "network_profile")
	some np in np_blocks

	not tf.has_key(np, "network_policy")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' does not have network_policy set in network_profile", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Invalid network_policy value
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "network_profile")
	np_blocks := tf.sub_blocks(block, "network_profile")
	some np in np_blocks

	policy := tf.string_attr(np, "network_policy")
	not policy in valid_policies

	line_num := tf.line_number(content, np, "network_policy")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' has invalid network_policy '%s'. Use 'azure' or 'calico'", [name, policy]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
