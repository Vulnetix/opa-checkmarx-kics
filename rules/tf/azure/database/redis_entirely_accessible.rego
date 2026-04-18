# KICS-TF-AZURE-013
# Ported from: redis_entirely_accessible
# Severity: Critical

package vulnetix.rules.kics_tf_azure_redis_entirely_accessible

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-013",
	"name": "Redis Cache entirely accessible to internet",
	"description": "Azure Redis Cache firewall rule allows access from any IP address (0.0.0.0). This exposes the cache to the entire internet and potential unauthorized access.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "redis", "public-access", "firewall", "0.0.0.0", "internet"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_redis_firewall_rule")
	block := rb.block
	name := rb.name

	start_ip := tf.string_attr(block, "start_ip")
	end_ip := tf.string_attr(block, "end_ip")

	# Both are 0.0.0.0 (allows any IP)
	start_ip == "0.0.0.0"
	end_ip == "0.0.0.0"

	line_num := tf.line_number(content, block, "start_ip")
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis firewall rule '%s' is entirely accessible from the internet (0.0.0.0)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
