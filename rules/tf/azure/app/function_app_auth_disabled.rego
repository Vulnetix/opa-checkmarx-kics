# KICS-TF-AZURE-023
# Ported from: function_app_authentication_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_function_app_auth_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-023",
	"name": "Function App authentication disabled",
	"description": "Azure Function App does not have authentication enabled. This means the functions are accessible without requiring authentication, potentially exposing sensitive functionality.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287", "CWE-306"],
	"tags": ["azure", "function-app", "authentication", "security"],
}

func_types := {"azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app"}

# Legacy azurerm_function_app - missing auth_settings
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_function_app")
	block := rb.block
	name := rb.name

	not tf.has_sub_block(block, "auth_settings")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function App '%s' does not have authentication configured. Add auth_settings block with enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Legacy azurerm_function_app - auth_settings.enabled = false
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_function_app")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "auth_settings")
	as_blocks := tf.sub_blocks(block, "auth_settings")
	some auth in as_blocks

	enabled := tf.bool_attr(auth, "enabled")
	enabled == false

	line_num := tf.line_number(content, auth, "enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function App '%s' has authentication disabled (auth_settings.enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Linux/Windows Function Apps - missing auth_settings_v2
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_linux_function_app", "azurerm_windows_function_app"}
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	not tf.has_sub_block(block, "auth_settings_v2")
	not tf.has_sub_block(block, "auth_settings")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function App '%s' does not have authentication configured. Add auth_settings_v2 block with auth_enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Linux/Windows Function Apps - auth_settings_v2.auth_enabled = false
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_linux_function_app", "azurerm_windows_function_app"}
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "auth_settings_v2")
	asv2_blocks := tf.sub_blocks(block, "auth_settings_v2")
	some asv2 in asv2_blocks

	auth_enabled := tf.bool_attr(asv2, "auth_enabled")
	auth_enabled == false

	line_num := tf.line_number(content, asv2, "auth_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function App '%s' has authentication v2 disabled (auth_settings_v2.auth_enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
