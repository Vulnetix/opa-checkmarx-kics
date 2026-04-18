# KICS-TF-AZURE-015
# Ported from: blob_storage_without_soft_delete
# Severity: Medium

package vulnetix.rules.kics_tf_azure_blob_without_soft_delete

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-015",
	"name": "Blob storage without soft delete",
	"description": "Azure Storage Account does not have soft delete enabled for blobs. Without soft delete, deleted blobs cannot be recovered in case of accidental deletion or malicious activity.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1288"],
	"tags": ["azure", "storage", "blob", "soft-delete", "data-protection"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_storage_account")
	block := rb.block
	name := rb.name

	# blob_properties block not defined
	not tf.has_sub_block(block, "blob_properties")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account '%s' does not have blob soft delete configured. Add blob_properties with delete_retention_policy", [name]),
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
	some rb in tf.resource_blocks(content, "azurerm_storage_account")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "blob_properties")
	bp_blocks := tf.sub_blocks(block, "blob_properties")
	some bp in bp_blocks

	# delete_retention_policy not defined
	not tf.has_sub_block(bp, "delete_retention_policy")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 10)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account '%s' blob properties do not include delete retention policy", [name]),
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
	some rb in tf.resource_blocks(content, "azurerm_storage_account")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "blob_properties")
	bp_blocks := tf.sub_blocks(block, "blob_properties")
	some bp in bp_blocks

	tf.has_sub_block(bp, "delete_retention_policy")
	drp_blocks := tf.sub_blocks(bp, "delete_retention_policy")
	some drp in drp_blocks

	# days is 0 or not set (effectively disabled)
	days := tf.number_attr(drp, "days")
	days == 0

	line_num := tf.line_number(content, drp, "days")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account '%s' has blob soft delete disabled (days = 0)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
