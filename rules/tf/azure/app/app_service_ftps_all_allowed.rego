# KICS-TF-AZURE-036
# Ported from: app_service_ftps_enforce_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_app_service_ftps_all_allowed

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-036",
	"name": "App Service FTPS allowing all connections",
	"description": "Azure App Service allows all FTP connections (including unencrypted). FTPS should be enforced to ensure data is transmitted securely.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319", "CWE-326"],
	"tags": ["azure", "appservice", "webapp", "ftps", "ftp", "encryption"],
}

app_types := {"azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in app_types
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "site_config")
	sc_blocks := tf.sub_blocks(block, "site_config")
	some sc in sc_blocks

	ftps_state := tf.string_attr(sc, "ftps_state")
	ftps_state == "AllAllowed"

	line_num := tf.line_number(content, sc, "ftps_state")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service '%s' allows all FTP connections. Set ftps_state to 'FtpsOnly' or 'Disabled'", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
