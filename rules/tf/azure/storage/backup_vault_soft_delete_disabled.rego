# KICS-TF-AZURE-024
# Ported from: backup_vault_without_soft_delete
# Severity: Medium

package vulnetix.rules.kics_tf_azure_backup_vault_soft_delete_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-024",
	"name": "Backup vault soft delete disabled",
	"description": "Azure Backup Vault has soft delete disabled. Without soft delete, backed-up data can be permanently deleted without the ability to recover, increasing risk during ransomware attacks or accidental deletions.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1288"],
	"tags": ["azure", "backup", "vault", "soft-delete", "data-protection"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_data_protection_backup_vault")
	block := rb.block
	name := rb.name

	# soft_delete is "off" or not set (varies by default)
	soft_delete := tf.string_attr(block, "soft_delete")
	soft_delete == "Off"

	line_num := tf.line_number(content, block, "soft_delete")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Backup vault '%s' has soft delete disabled (soft_delete = 'Off'). Set to 'On' or 'AlwaysOn'", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
