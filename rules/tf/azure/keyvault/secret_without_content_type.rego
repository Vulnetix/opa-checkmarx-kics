# KICS-TF-AZURE-042
# Ported from: key_vault_secrets_content_type_undefined
# Severity: Low

package vulnetix.rules.kics_tf_azure_secret_without_content_type

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-042",
	"name": "Key Vault secret without content type",
	"description": "Azure Key Vault secret does not have a content type specified. Content types help applications understand how to interpret secret values.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": [],
	"tags": ["azure", "keyvault", "secret", "content-type"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_key_vault_secret")
	block := rb.block
	name := rb.name

	# content_type not set
	not tf.has_key(block, "content_type")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault secret '%s' does not have content_type specified. Add content_type to help consumers understand the secret format", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
