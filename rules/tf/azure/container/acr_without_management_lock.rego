# KICS-TF-AZURE-046
# Ported from: azure_container_registry_with_no_locks
# Severity: Medium

package vulnetix.rules.kics_tf_azure_acr_without_lock

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-046",
	"name": "Container Registry without management lock",
	"description": "Azure Container Registry does not have a management lock applied. Management locks prevent accidental deletion or modification of critical resources.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1288"],
	"tags": ["azure", "container-registry", "acr", "lock", "resource-protection"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_container_registry")
	block := rb.block
	name := rb.name

	# Check if there's no management lock for this ACR
	# This is a best-effort check since management locks can reference resources
	not has_management_lock(content, name)

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container registry '%s' does not have a management lock applied. Add azurerm_management_lock with scope referencing this registry", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

has_management_lock(content, name) if {
	# Check if any management lock resource references this registry
	pattern := sprintf(`azurerm_container_registry\.%s`, [name])
	regex.match(pattern, content)
	regex.match(`azurerm_management_lock`, content)
}
