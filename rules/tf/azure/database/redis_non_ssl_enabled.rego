# KICS-TF-AZURE-021
# Ported from: redis_cache_allows_non_ssl_connections
# Severity: Medium

package vulnetix.rules.kics_tf_azure_redis_non_ssl_enabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-021",
	"name": "Redis Cache non-SSL port enabled",
	"description": "Azure Redis Cache has the non-SSL port (6379) enabled. This allows unencrypted connections to the cache, exposing data in transit to eavesdropping.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319", "CWE-326"],
	"tags": ["azure", "redis", "ssl", "encryption", "cache"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_redis_cache")
	block := rb.block
	name := rb.name

	# enable_non_ssl_port is true
	enabled := tf.bool_attr(block, "enable_non_ssl_port")
	enabled == true

	line_num := tf.line_number(content, block, "enable_non_ssl_port")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis Cache '%s' has non-SSL port enabled. Set enable_non_ssl_port = false to enforce encrypted connections", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
