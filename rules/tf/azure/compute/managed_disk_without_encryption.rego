# KICS-TF-AZURE-041
# Ported from: disk_encryption_on_managed_disk_disabled
# Severity: High

package vulnetix.rules.kics_tf_azure_managed_disk_without_encryption

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-041",
	"name": "Managed disk without customer-managed encryption",
	"description": "Azure Managed Disk does not use customer-managed encryption keys (disk encryption set). Without disk encryption sets, the disk uses platform-managed keys which may not meet certain compliance requirements.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311", "CWE-326"],
	"tags": ["azure", "compute", "disk", "encryption", "cmk"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_managed_disk")
	block := rb.block
	name := rb.name

	# disk_encryption_set_id not set
	not tf.has_key(block, "disk_encryption_set_id")

	# Also check secure_vm_disk_encryption_set_id for confidential VMs
	not tf.has_key(block, "secure_vm_disk_encryption_set_id")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Managed disk '%s' does not use customer-managed encryption. Add disk_encryption_set_id", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
