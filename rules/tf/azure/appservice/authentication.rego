# Ported from checkmarx-kics: app_service_authentication_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_azure_appservice_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AZURE-APPSERVICE-01",
	"name": "App Service Authentication should be enabled",
	"description": "Azure App Service (Web Apps) should have authentication enabled via auth_settings or auth_settings_v2 blocks.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "appservice", "authentication", "security"],
}

# Check for azurerm_app_service (legacy) - missing auth_settings
findings contains finding if {
	some r in tf.resources("azurerm_app_service")
	not tf.has_sub_block(r.block, "auth_settings")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("azurerm_app_service %q is missing auth_settings block.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

# auth_settings but enabled = false
findings contains finding if {
	some r in tf.resources("azurerm_app_service")
	tf.has_sub_block(r.block, "auth_settings")
regex.match(`(?s)auth_settings(?i)\s*\{[^\}]*enabled(?i)\s*=\s*false`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("azurerm_app_service %q has auth_settings.enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}

# Check for azurerm_linux_web_app / azurerm_windows_web_app - missing both auth_settings
findings contains finding if {
	some rtype in ["azurerm_linux_web_app", "azurerm_windows_web_app"]
	some r in tf.resources(rtype)
	not tf.has_sub_block(r.block, "auth_settings")
	not tf.has_sub_block(r.block, "auth_settings_v2")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q is missing auth_settings or auth_settings_v2 block.", [rtype, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

# auth_settings_v2 but auth_enabled = false
findings contains finding if {
	some rtype in ["azurerm_linux_web_app", "azurerm_windows_web_app"]
	some r in tf.resources(rtype)
	tf.has_sub_block(r.block, "auth_settings_v2")
regex.match(`(?s)auth_settings_v2(?i)\s*\{[^\}]*auth_enabled(?i)\s*=\s*false`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q has auth_settings_v2.auth_enabled = false.", [rtype, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}
