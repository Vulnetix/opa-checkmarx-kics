# KICS-TF-AZURE-009
# Ported from: postgresql_not_using_latest_tls_encryption_version
# Severity: Medium

package vulnetix.rules.kics_tf_azure_postgresql_outdated_tls

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-009",
	"name": "PostgreSQL using outdated TLS version",
	"description": "Azure PostgreSQL server is configured to use an outdated TLS version. TLS versions below 1.2 have known vulnerabilities and should not be used for production databases.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319", "CWE-326"],
	"tags": ["azure", "database", "postgresql", "tls", "encryption"],
}

# For azurerm_postgresql_server resource
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_server")
	block := rb.block
	name := rb.name

	# ssl_minimal_tls_version_enforced is set to outdated version
	tls_version := tf.string_attr(block, "ssl_minimal_tls_version_enforced")
	tls_version in ["TLS1_0", "TLS1_1"]

	line_num := tf.line_number(content, block, "ssl_minimal_tls_version_enforced")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server '%s' uses TLS %s. Use TLS1_2 or higher", [name, tls_version]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Check when TLS version is not specified (defaults may be outdated in some regions)
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_server")
	block := rb.block
	name := rb.name

	# ssl_minimal_tls_version_enforced not defined
	not tf.has_key(block, "ssl_minimal_tls_version_enforced")
	# But ssl_enforcement_enabled is explicitly true
	tf.bool_attr(block, "ssl_enforcement_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server '%s' does not specify minimal TLS version. Set ssl_minimal_tls_version_enforced = 'TLS1_2'", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# For azurerm_postgresql_flexible_server resource
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_flexible_server")
	block := rb.block
	name := rb.name

	# ssl_minimal_tls_version_enforced is set to outdated version
	tls_version := tf.string_attr(block, "ssl_minimal_tls_version_enforced")
	tls_version in ["TLS1_0", "TLS1_1"]

	line_num := tf.line_number(content, block, "ssl_minimal_tls_version_enforced")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL flexible server '%s' uses TLS %s. Use TLS1_2 or higher", [name, tls_version]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
