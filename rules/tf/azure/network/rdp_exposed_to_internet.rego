# KICS-TF-AZURE-003
# Ported from: rdp_is_exposed_to_the_internet
# Severity: Critical

package vulnetix.rules.kics_tf_azure_rdp_exposed_to_internet

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-003",
	"name": "RDP exposed to the internet",
	"description": "Network security rule or group allows RDP (port 3389) access from the internet. This exposes Windows systems to brute force attacks and remote code execution.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["azure", "network", "security-group", "rdp", "port-3389"],
}

# Check azurerm_network_security_rule resources
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_network_security_rule")
	block := rb.block
	name := rb.name

	# Check if rule allows inbound RDP
	is_allow_inbound_rdp(block)

	line_num := tf.line_number(content, block, "destination_port_range")
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Network security rule '%s' allows RDP (port 3389) access from the internet", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

is_allow_inbound_rdp(block) if {
	tf.string_attr(block, "access") == "Allow"
	tf.string_attr(block, "direction") == "Inbound"
	port := tf.string_attr(block, "destination_port_range")
	is_rdp_port(port)
	prefix := tf.string_attr(block, "source_address_prefix")
	is_internet_prefix(prefix)
}

default is_allow_inbound_rdp(_) := false

# Check security_rule blocks within azurerm_network_security_group
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_network_security_group")
	block := rb.block
	name := rb.name

	pattern := `(?s)security_rule\s*\{((?:[^{}]|\{[^{}]*\})*?)\}`
	rule_blocks := regex.find_n(pattern, block, -1)
	some rule in rule_blocks

	tf.string_attr(rule, "access") == "Allow"
	tf.string_attr(rule, "direction") == "Inbound"
	port := tf.string_attr(rule, "destination_port_range")
	is_rdp_port(port)
	prefix := tf.string_attr(rule, "source_address_prefix")
	is_internet_prefix(prefix)

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	rule_name := tf.string_attr(rule, "name")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Network security group '%s' contains rule '%s' allowing RDP (port 3389) from the internet", [name, rule_name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

is_rdp_port(port) if {
	port == "3389"
}

is_rdp_port(port) if {
	port == "*"
}

is_rdp_port(port) if {
	regex.match(`(^|\s|,)3389(-|,|$|\s)`, port)
}

is_rdp_port(port) if {
	regex.match(`-\s*3389`, port)
	ports := split(port, "-")
	to_number(trim(ports[0], " ")) <= 3389
	to_number(trim(ports[1], " ")) >= 3389
}

is_internet_prefix(prefix) if {
	prefix == "*"
}

is_internet_prefix(prefix) if {
	prefix == "0.0.0.0"
}

is_internet_prefix(prefix) if {
	endswith(prefix, "/0")
}

is_internet_prefix(prefix) if {
	lower(prefix) == "internet"
}

is_internet_prefix(prefix) if {
	lower(prefix) == "any"
}
