# KICS-TF-AZURE-031
# Ported from: aks_disk_encryption_set_id_undefined
# Severity: High

package vulnetix.rules.kics_tf_azure_aks_disk_encryption_missing

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-031",
	"name": "AKS node pool disk encryption not configured",
	"description": "Azure Kubernetes Service cluster does not specify a disk encryption set for node pool disks. Without customer-managed keys, node disks use platform-managed keys which may not meet organizational security requirements.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311", "CWE-326"],
	"tags": ["azure", "kubernetes", "aks", "disk-encryption", "cmk"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_kubernetes_cluster")
	block := rb.block
	name := rb.name

	# disk_encryption_set_id not set
	not tf.has_key(block, "disk_encryption_set_id")

	# Check if using non-ephemeral disk
	not uses_ephemeral_disk(block)

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster '%s' does not specify disk encryption set. Add disk_encryption_set_id with customer-managed key", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

uses_ephemeral_disk(block) if {
	tf.has_sub_block(block, "default_node_pool")
	dnp_blocks := tf.sub_blocks(block, "default_node_pool")
	some dnp in dnp_blocks

	os_disk_type := tf.string_attr(dnp, "os_disk_type")
	os_disk_type == "Ephemeral"
}
