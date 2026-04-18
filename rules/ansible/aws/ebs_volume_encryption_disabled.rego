# Ported from checkmarx-kics/rules/ansible/aws/ebs_volume_encryption_disabled
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_ebs_encryption_disabled

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-ENC-001",
	"name": "EBS volume encryption disabled",
	"description": "EBS volumes should be encrypted to protect sensitive data at rest.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_vol_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "ebs", "ec2", "encryption"],
}

# Check for ec2_vol module with encrypted: false or encrypted not set
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "ec2_vol")
	some task in tasks

	# Check if encrypted attribute is explicitly false
	val := ansible.string_attr(task, "encrypted")
	ansible.is_false(val)

	not regex.match(`state:\s*(absent|list)`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS volume '%s' has encryption explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Check for missing encrypted attribute
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "ec2_vol")
	some task in tasks

	# Check if encrypted attribute is not present
	not ansible.has_key(task, "encrypted")
	not regex.match(`state:\s*(absent|list)`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS volume '%s' does not have encryption enabled (encrypted attribute missing)", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# amazon.aws.ec2_vol module
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "amazon.aws.ec2_vol")
	some task in tasks

	val := ansible.string_attr(task, "encrypted")
	ansible.is_false(val)
	not regex.match(`state:\s*(absent|list)`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS volume '%s' has encryption explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "amazon.aws.ec2_vol")
	some task in tasks

	not ansible.has_key(task, "encrypted")
	not regex.match(`state:\s*(absent|list)`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS volume '%s' does not have encryption enabled (encrypted attribute missing)", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
