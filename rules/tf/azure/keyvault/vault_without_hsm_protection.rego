# KICS-TF-AZURE-035
# Ported from: key_vault_without_hsm_protection
# Severity: Medium

package vulnetix.rules.kics_tf_azure_key_vault_without_hsm

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-035",
	"name": "Key Vault without HSM protection",
	"description": "Azure Key Vault is not using HSM-backed keys (Premium tier). Standard tier uses software-protected keys which may not meet certain compliance requirements that mandate hardware security modules.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"tags": ["azure", "keyvault", "hsm", "premium", "compliance"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_key_vault")
	block := rb.block
	name := rb.name

	# sku_name is not Premium
	sku := tf.string_attr(block, "sku_name")
	sku != "premium"
	not sku == "Premium"

	line_num := tf.line_number(content, block, "sku_name")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault '%s' uses '%s' tier. Use 'premium' tier for HSM-backed keys", [name, sku]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Also check when sku_name is missing
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_key_vault")
	block := rb.block
	name := rb.name

	not tf.has_key(block, "sku_name")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault '%s' does not explicitly set SKU tier. Add sku_name = 'premium' for HSM-backed keys", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
