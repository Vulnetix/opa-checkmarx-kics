# KICS-TF-AZURE-034
# Ported from: network_watcher_flow_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_network_watcher_flow_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-034",
	"name": "Network Watcher flow logs disabled",
	"description": "Azure Network Watcher flow logs are not configured. Flow logs provide information about IP traffic flowing through network security groups and are essential for network monitoring and security analysis.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["azure", "network", "watcher", "flow-logs", "monitoring"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_network_watcher_flow_log")
	block := rb.block
	name := rb.name

	# enabled is false
	enabled := tf.bool_attr(block, "enabled")
	enabled == false

	line_num := tf.line_number(content, block, "enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Network Watcher flow log '%s' is disabled (enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
