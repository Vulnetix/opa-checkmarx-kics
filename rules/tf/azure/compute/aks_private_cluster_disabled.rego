# KICS-TF-AZURE-005
# Ported from: aks_private_cluster_disabled
# Severity: High

package vulnetix.rules.kics_tf_azure_aks_private_cluster_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-005",
	"name": "AKS private cluster disabled",
	"description": "Azure Kubernetes Service cluster does not have private cluster enabled. The API server is publicly accessible over the internet, increasing the attack surface.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "kubernetes", "aks", "private-cluster", "network"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	# private_cluster_enabled not defined
	not tf.has_key(block, "private_cluster_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' does not have private cluster enabled. Add private_cluster_enabled = true", [name]),
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

	# private_cluster_enabled explicitly set to false
	enabled := tf.bool_attr(block, "private_cluster_enabled")
	enabled == false

	line_num := tf.line_number(content, block, "private_cluster_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' has private_cluster_enabled = false. The API server is publicly accessible", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
