# KICS-TF-AZURE-018
# Ported from: app_service_not_using_latest_tls_encryption_version
# Severity: Medium

package vulnetix.rules.kics_tf_azure_app_service_tls_version

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-018",
	"name": "App Service using outdated TLS version",
	"description": "Azure App Service is configured to use an outdated TLS version. TLS 1.0 and 1.1 have known vulnerabilities and should not be used. Configure the minimum TLS version to 1.2 or higher.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319", "CWE-326"],
	"tags": ["azure", "appservice", "webapp", "tls", "encryption"],
}

resource_types := {"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service"}

outdated_tls := {"1.0", "1.1", "TLS1_0", "TLS1_1"}

# azurerm_app_service - site_config.min_tls_version
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_app_service")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "site_config")
	sc_blocks := tf.sub_blocks(block, "site_config")
	some sc in sc_blocks

	tls_version := tf.string_attr(sc, "min_tls_version")
	tls_version in outdated_tls

	line_num := tf.line_number(content, sc, "min_tls_version")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service '%s' uses TLS %s. Set min_tls_version to '1.2' or higher", [name, tls_version]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# azurerm_linux_web_app / azurerm_windows_web_app
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_linux_web_app", "azurerm_windows_web_app"}
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "site_config")
	sc_blocks := tf.sub_blocks(block, "site_config")
	some sc in sc_blocks

	tls_version := tf.string_attr(sc, "minimum_tls_version")
	tls_version in outdated_tls

	line_num := tf.line_number(content, sc, "minimum_tls_version")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Web App '%s' uses TLS %s. Set minimum_tls_version to '1.2' or higher", [name, tls_version]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Default/missing TLS version (azurerm_app_service)
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_app_service")
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "site_config")
	sc_blocks := tf.sub_blocks(block, "site_config")
	some sc in sc_blocks

	not tf.has_key(sc, "min_tls_version")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 10)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service '%s' does not explicitly set minimum TLS version. Add min_tls_version = '1.2' to site_config", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Default/missing TLS version (linux/windows web apps)
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_linux_web_app", "azurerm_windows_web_app"}
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "site_config")
	sc_blocks := tf.sub_blocks(block, "site_config")
	some sc in sc_blocks

	not tf.has_key(sc, "minimum_tls_version")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 10)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Web App '%s' does not explicitly set minimum TLS version. Add minimum_tls_version = '1.2' to site_config", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
