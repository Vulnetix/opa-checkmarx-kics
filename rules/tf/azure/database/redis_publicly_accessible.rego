# KICS-TF-AZURE-012
# Ported from: redis_publicly_accessible
# Severity: High

package vulnetix.rules.kics_tf_azure_redis_publicly_accessible

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-012",
	"name": "Redis Cache publicly accessible",
	"description": "Azure Redis Cache firewall rules allow access from public IP addresses. Redis instances should only be accessible from private networks or specific trusted IPs.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "redis", "public-access", "firewall", "cache"],
}

# Private IP ranges
is_private_ip(ip) if {
	startswith(ip, "10.")
}

is_private_ip(ip) if {
	startswith(ip, "172.")
	octet2 := to_number(split(ip, ".")[1])
	octet2 >= 16
	octet2 <= 31
}

is_private_ip(ip) if {
	startswith(ip, "192.168.")
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_redis_firewall_rule")
	block := rb.block
	name := rb.name

	start_ip := tf.string_attr(block, "start_ip")
	end_ip := tf.string_attr(block, "end_ip")

	# Both IPs are not private
	not is_private_ip(start_ip)
	not is_private_ip(end_ip)

	line_num := tf.line_number(content, block, "start_ip")
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis firewall rule '%s' allows public IP range %s - %s", [name, start_ip, end_ip]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
