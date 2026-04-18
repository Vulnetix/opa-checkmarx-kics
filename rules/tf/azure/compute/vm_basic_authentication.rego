# KICS-TF-AZURE-032
# Ported from: azure_instance_using_basic_authentication
# Severity: High

package vulnetix.rules.kics_tf_azure_vm_basic_authentication

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-032",
	"name": "Virtual machine using basic authentication",
	"description": "Azure Virtual Machine has password authentication enabled for Linux instances. Password authentication is vulnerable to brute force attacks and should be disabled in favor of SSH key-based authentication.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-287", "CWE-798"],
	"tags": ["azure", "compute", "vm", "authentication", "password", "ssh"],
}

# Legacy azurerm_virtual_machine and azurerm_virtual_machine_scale_set
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_virtual_machine", "azurerm_virtual_machine_scale_set"}
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	tf.has_sub_block(block, "os_profile_linux_config")
	oplc_blocks := tf.sub_blocks(block, "os_profile_linux_config")
	some oplc in oplc_blocks

	# disable_password_authentication is false or missing
	enabled := tf.bool_attr(oplc, "disable_password_authentication")
	enabled == false

	line_num := tf.line_number(content, oplc, "disable_password_authentication")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM '%s' has password authentication enabled (disable_password_authentication = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Newer azurerm_linux_virtual_machine and azurerm_linux_virtual_machine_scale_set
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some type in {"azurerm_linux_virtual_machine", "azurerm_linux_virtual_machine_scale_set"}
	some rb in tf.resource_blocks(content, type)
	block := rb.block
	name := rb.name

	# disable_password_authentication is false
	enabled := tf.bool_attr(block, "disable_password_authentication")
	enabled == false

	line_num := tf.line_number(content, block, "disable_password_authentication")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Linux VM '%s' has password authentication enabled. Set disable_password_authentication = true and use SSH keys", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
