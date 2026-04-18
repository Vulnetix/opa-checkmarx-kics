# KICS-TF-AZURE-033
# Ported from: email_alerts_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_security_center_email_alerts_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-033",
	"name": "Security Center email alerts disabled",
	"description": "Azure Security Center contact has email alerts disabled. Security alerts notify administrators of potential security threats and should be enabled for timely response.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["azure", "security-center", "alerts", "email", "notifications"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_security_center_contact")
	block := rb.block
	name := rb.name

	# alert_notifications is false
	enabled := tf.bool_attr(block, "alert_notifications")
	enabled == false

	line_num := tf.line_number(content, block, "alert_notifications")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security Center contact '%s' has email alerts disabled (alert_notifications = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
