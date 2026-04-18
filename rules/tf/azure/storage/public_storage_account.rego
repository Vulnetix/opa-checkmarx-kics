# KICS-TF-AZURE-001
# Ported from: public_storage_account
# Severity: Critical

package vulnetix.rules.kics_tf_azure_public_storage_account

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-001",
	"name": "Public storage account access",
	"description": "Azure Storage Account has overly permissive network access, allowing public access from the internet. This exposes sensitive data to potential unauthorized access.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "storage", "network", "public-access"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_storage_account")
	block := rb.block
	name := rb.name

	# Check for allow_blob_public_access = true
	tf.bool_attr(block, "allow_blob_public_access")

	line_num := tf.line_number(content, block, "allow_blob_public_access")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account '%s' has public blob access enabled, exposing data to the internet", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_storage_account")
	block := rb.block
	name := rb.name

	# Check for network_rules with default_action = Allow and ip_rules containing 0.0.0.0/0
	not tf.has_sub_block(block, "network_rules")
	not tf.has_key(block, "allow_blob_public_access")

	default_action := tf.string_attr(block, "network_rules.default_action")
	default_action == "Allow"

	ip_rules := tf.string_list_attr(block, "network_rules.ip_rules")
	"0.0.0.0/0" in ip_rules

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account '%s' allows unrestricted network access from the internet (0.0.0.0/0)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_storage_account_network_rules")
	block := rb.block
	name := rb.name

	# Check for standalone network rules with 0.0.0.0/0
	ip_rules := tf.string_list_attr(block, "ip_rules")
	"0.0.0.0/0" in ip_rules

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account network rules '%s' allow access from any IP (0.0.0.0/0)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_storage_account_network_rules")
	block := rb.block
	name := rb.name

	# Check for default_action = Allow without ip_rules restriction
	not tf.has_key(block, "ip_rules")
	default_action := tf.string_attr(block, "default_action")
	default_action == "Allow"

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account network rules '%s' have permissive default action (Allow) without IP restrictions", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
