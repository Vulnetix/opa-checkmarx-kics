# KICS-TF-AZURE-025
# Ported from: mssql_not_using_latest_tls_encryption_version
# Severity: Medium

package vulnetix.rules.kics_tf_azure_mssql_outdated_tls

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-025",
	"name": "MSSQL using outdated TLS version",
	"description": "Azure SQL Server is configured to use an outdated TLS version. TLS versions below 1.2 have known vulnerabilities and should not be used for production databases.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319", "CWE-326"],
	"tags": ["azure", "database", "mssql", "tls", "encryption"],
}

outdated_tls := {"1.0", "1.1", "TLS1_0", "TLS1_1"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mssql_server")
	block := rb.block
	name := rb.name

	# Minimum TLS version set to outdated version
	min_tls := tf.string_attr(block, "minimum_tls_version")
	min_tls in outdated_tls

	line_num := tf.line_number(content, block, "minimum_tls_version")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server '%s' uses TLS %s. Set minimum_tls_version to '1.2'", [name, min_tls]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Check when TLS version is not explicitly set
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mssql_server")
	block := rb.block
	name := rb.name

	not tf.has_key(block, "minimum_tls_version")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server '%s' does not explicitly set minimum TLS version. Add minimum_tls_version = '1.2'", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
