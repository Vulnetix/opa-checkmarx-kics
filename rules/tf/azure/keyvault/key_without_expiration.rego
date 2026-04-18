# KICS-TF-AZURE-020
# Ported from: key_expiration_not_set
# Severity: Medium

package vulnetix.rules.kics_tf_azure_key_without_expiration

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-020",
	"name": "Key Vault key without expiration date",
	"description": "Azure Key Vault key does not have an expiration date set. Keys without expiration increase risk if the key is compromised, as there is no automatic rotation or expiration.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"tags": ["azure", "keyvault", "key", "expiration", "rotation"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_key_vault_key")
	block := rb.block
	name := rb.name

	# expiration_date not set
	not tf.has_key(block, "expiration_date")
	not tf.has_key(block, "expire")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault key '%s' does not have an expiration date. Add expiration_date", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
