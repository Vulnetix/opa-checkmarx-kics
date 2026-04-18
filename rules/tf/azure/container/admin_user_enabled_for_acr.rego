# KICS-TF-AZURE-019
# Ported from: admin_user_enabled_for_container_registry
# Severity: High

package vulnetix.rules.kics_tf_azure_acr_admin_user_enabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-019",
	"name": "ACR admin user enabled",
	"description": "Azure Container Registry has admin user enabled. The admin account is a single shared account for the registry, providing single-factor authentication. Use Azure AD-based authentication or service principals instead.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-287", "CWE-798"],
	"tags": ["azure", "container-registry", "acr", "admin-user", "authentication"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_container_registry")
	block := rb.block
	name := rb.name

	# admin_enabled is true
	enabled := tf.bool_attr(block, "admin_enabled")
	enabled == true

	line_num := tf.line_number(content, block, "admin_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container registry '%s' has admin user enabled. Disable admin_enabled and use Azure AD authentication", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
