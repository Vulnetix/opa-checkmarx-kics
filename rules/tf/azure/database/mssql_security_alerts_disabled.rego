# KICS-TF-AZURE-043
# Ported from: mssql_server_database_with_alerts_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_mssql_security_alerts_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-043",
	"name": "MSSQL security alerts disabled",
	"description": "Azure SQL Server does not have security alert policy enabled or has alerts disabled. Security alerts notify administrators of suspicious database activities and potential security threats.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["azure", "database", "mssql", "security-alerts", "threat-detection"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mssql_server")
	block := rb.block
	name := rb.name

	# Check if security alert policy resource is missing (using a simple check)
	# In KICS this checks across the whole document, here we just check the server config
	not tf.has_sub_block(block, "security_alert_policy")
	not tf.has_key(block, "security_alert_policy_id")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server '%s' does not have security alert policy configured. Add azurerm_mssql_server_security_alert_policy resource", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mssql_server_security_alert_policy")
	block := rb.block
	name := rb.name

	# state is not Enabled
	state := tf.string_attr(block, "state")
	not state == "Enabled"
	not state == "enabled"

	line_num := tf.line_number(content, block, "state")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL security alert policy '%s' is not enabled (state = '%s')", [name, state]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
