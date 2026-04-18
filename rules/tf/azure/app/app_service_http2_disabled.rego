# KICS-TF-AZURE-037
# Ported from: app_service_http2_disabled
# Severity: Low

package vulnetix.rules.kics_tf_azure_app_service_http2_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-037",
	"name": "App Service HTTP/2 disabled",
	"description": "Azure App Service does not have HTTP/2 enabled. HTTP/2 provides performance improvements and better security features compared to HTTP/1.1.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": [],
	"tags": ["azure", "appservice", "webapp", "http2", "performance"],
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

	# http2_enabled is false
	enabled := tf.bool_attr(sc, "http2_enabled")
	enabled == false

	line_num := tf.line_number(content, sc, "http2_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service '%s' has HTTP/2 disabled. Set http2_enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Check when http2_enabled is not set
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

	not tf.has_key(sc, "http2_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service '%s' does not explicitly enable HTTP/2. Add http2_enabled = true to site_config", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
