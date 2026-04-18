# KICS-TF-AZURE-040
# Ported from: container_instances_not_using_private_virtual_networks
# Severity: Medium

package vulnetix.rules.kics_tf_azure_container_group_public_ip

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-040",
	"name": "Container Group using public IP address",
	"description": "Azure Container Group is configured with public IP address type. For sensitive workloads, use private IP addresses within a virtual network.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "container", "aci", "public-ip", "network"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_container_group")
	block := rb.block
	name := rb.name

	# ip_address_type is not Private
	ip_type := tf.string_attr(block, "ip_address_type")
	not ip_type == "Private"
	not ip_type == "None"

	line_num := tf.line_number(content, block, "ip_address_type")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container group '%s' has public IP address type ('%s'). Use 'Private' for secure workloads", [name, ip_type]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
