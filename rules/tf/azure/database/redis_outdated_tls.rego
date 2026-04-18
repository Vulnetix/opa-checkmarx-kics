# KICS-TF-AZURE-048
# Ported from: redis_cache_not_using_latest_tls_encryption_version
# Severity: Medium

package vulnetix.rules.kics_tf_azure_redis_outdated_tls

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-048",
	"name": "Redis Cache using outdated TLS version",
	"description": "Azure Redis Cache is configured to use an outdated TLS version. TLS 1.0 and 1.1 have known vulnerabilities. Configure minimum TLS version to 1.2.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319", "CWE-326"],
	"tags": ["azure", "redis", "tls", "encryption", "cache"],
}

outdated_tls := {"1.0", "1.1", "TLS1_0", "TLS1_1"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_redis_cache")
	block := rb.block
	name := rb.name

	# minimum_tls_version set to outdated version
	min_tls := tf.string_attr(block, "minimum_tls_version")
	min_tls in outdated_tls

	line_num := tf.line_number(content, block, "minimum_tls_version")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis Cache '%s' uses TLS %s. Set minimum_tls_version to '1.2'", [name, min_tls]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
