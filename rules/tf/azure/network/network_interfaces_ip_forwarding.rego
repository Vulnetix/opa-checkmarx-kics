# KICS-TF-AZURE-016
# Ported from: network_interfaces_ip_forwarding_enabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_network_interfaces_ip_forwarding

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-016",
	"name": "Network interface IP forwarding enabled",
	"description": "Azure Network Interface has IP forwarding enabled. This allows the VM to receive traffic not destined for its IP address, which can be abused for network traffic interception or man-in-the-middle attacks.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["azure", "network", "interface", "ip-forwarding", "security"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_network_interface")
	block := rb.block
	name := rb.name

	# ip_forwarding_enabled is true
	enabled := tf.bool_attr(block, "ip_forwarding_enabled")
	enabled == true

	line_num := tf.line_number(content, block, "ip_forwarding_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Network interface '%s' has IP forwarding enabled. Disable unless specifically required for routing scenarios", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Older attribute name
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_network_interface")
	block := rb.block
	name := rb.name

	# enable_ip_forwarding is true (older attribute)
	enabled := tf.bool_attr(block, "enable_ip_forwarding")
	enabled == true

	line_num := tf.line_number(content, block, "enable_ip_forwarding")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Network interface '%s' has IP forwarding enabled (enable_ip_forwarding = true)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
