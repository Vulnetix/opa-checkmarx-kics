# Ported from checkmarx-kics/rules/ansible/aws/cmk_rotation_disabled
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_kms_rotation_disabled

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-KMS-001",
	"name": "KMS key rotation disabled",
	"description": "AWS KMS keys should have automatic key rotation enabled to meet security and compliance requirements.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/community/aws/aws_kms_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-320"],
	"capec": [],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "kms", "encryption", "rotation"],
}

# Check for missing key rotation
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "aws_kms")
	some task in tasks

	# Check if enabled is true but rotation is not set
	enabled := ansible.string_attr(task, "enabled")
	ansible.is_true(enabled)
	not ansible.has_pending_window_or_rotation(task)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key '%s' does not have automatic key rotation configured", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Check for explicitly disabled rotation
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "aws_kms")
	some task in tasks

	enabled := ansible.string_attr(task, "enabled")
	ansible.is_true(enabled)
	not ansible.has_pending_window(task)
	rotation := ansible.string_attr(task, "enable_key_rotation")
	ansible.is_false(rotation)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key '%s' has automatic key rotation explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# community.aws.aws_kms variants
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "community.aws.aws_kms")
	some task in tasks

	enabled := ansible.string_attr(task, "enabled")
	ansible.is_true(enabled)
	not ansible.has_pending_window_or_rotation(task)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key '%s' does not have automatic key rotation configured", [ansible.task_name(task)]),
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

	tasks := ansible.tasks_with_module(content, "community.aws.aws_kms")
	some task in tasks

	enabled := ansible.string_attr(task, "enabled")
	ansible.is_true(enabled)
	not ansible.has_pending_window(task)
	rotation := ansible.string_attr(task, "enable_key_rotation")
	ansible.is_false(rotation)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key '%s' has automatic key rotation explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Helper functions
has_pending_window_or_rotation(block) if ansible.has_key(block, "pending_window")
has_pending_window_or_rotation(block) if ansible.has_key(block, "enable_key_rotation")
has_pending_window(block) if ansible.has_key(block, "pending_window")
