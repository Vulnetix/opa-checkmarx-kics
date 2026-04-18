# KICS-TF-AZURE-017
# Ported from: app_service_authentication_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_app_service_auth_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-017",
	"name": "App Service authentication disabled",
	"description": "Azure App Service (Web App) does not have authentication enabled. This means the application is accessible without requiring authentication, potentially exposing sensitive functionality.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287", "CWE-306"],
	"tags": ["azure", "appservice", "webapp", "authentication", "security"],
}

resource_types := {"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service"}

# Missing auth_settings v1
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in resource_types
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	# For azurerm_app_service (legacy), check auth_settings
	type == "azurerm_app_service"
	not tf.has_sub_block(block, "auth_settings")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service '%s' does not have authentication configured. Add auth_settings block with enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# auth_settings.disabled = true (legacy)
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_app_service")
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
		"message": sprintf("App Service '%s' has authentication disabled (auth_settings.enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Missing auth_settings v2 (for linux/windows web apps)
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_linux_web_app", "azurerm_windows_web_app"}
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	not tf.has_sub_block(block, "auth_settings_v2")
	not tf.has_sub_block(block, "auth_settings")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Web App '%s' does not have authentication configured. Add auth_settings_v2 block with auth_enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# auth_settings_v2.auth_enabled = false
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_linux_web_app", "azurerm_windows_web_app"}
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
		"message": sprintf("Web App '%s' has authentication v2 disabled (auth_settings_v2.auth_enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
