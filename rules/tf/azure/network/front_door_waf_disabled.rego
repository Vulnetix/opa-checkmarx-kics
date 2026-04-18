# KICS-TF-AZURE-038
# Ported from: azure_front_door_waf_disabled
# Severity: High

package vulnetix.rules.kics_tf_azure_front_door_waf_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-038",
	"name": "Front Door without Web Application Firewall",
	"description": "Azure Front Door frontend endpoint does not have a Web Application Firewall (WAF) policy linked. Without WAF, the application is vulnerable to common web attacks such as SQL injection and XSS.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["azure", "frontdoor", "cdn", "waf", "firewall", "web-security"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_frontdoor")
	block := rb.block
	name := rb.name

	# Check frontend_endpoint doesn't have WAF policy link
	tf.has_sub_block(block, "frontend_endpoint")
	fe_blocks := tf.sub_blocks(block, "frontend_endpoint")
	some fe in fe_blocks

	not tf.has_key(fe, "web_application_firewall_policy_link_id")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 10)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Front Door '%s' frontend endpoint does not have a WAF policy linked. Add web_application_firewall_policy_link_id", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
