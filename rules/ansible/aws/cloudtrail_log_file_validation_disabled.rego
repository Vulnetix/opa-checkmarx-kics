# Ported from checkmarx-kics/rules/ansible/aws/cloudtrail_log_file_validation_disabled
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_cloudtrail_validation_disabled

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-LOG-002",
	"name": "CloudTrail log file validation disabled",
	"description": "CloudTrail should have log file validation enabled to ensure log integrity.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/community/aws/cloudtrail_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-354"],
	"capec": [],
	"attack_technique": ["T1565"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "cloudtrail", "logging", "validation"],
}

# Check for cloudtrail module without log file validation
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "cloudtrail")
	some task in tasks

	# Check if neither enable_log_file_validation nor log_file_validation_enabled is set
	not ansible.has_key(task, "enable_log_file_validation")
	not ansible.has_key(task, "log_file_validation_enabled")
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' does not have log file validation enabled (missing attribute)", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Check for explicitly disabled log file validation
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "cloudtrail")
	some task in tasks

	# Check either attribute is explicitly false
	val1 := ansible.string_attr(task, "enable_log_file_validation")
	ansible.is_false(val1)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' has log file validation explicitly disabled", [ansible.task_name(task)]),
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

	tasks := ansible.tasks_with_module(content, "cloudtrail")
	some task in tasks

	val2 := ansible.string_attr(task, "log_file_validation_enabled")
	ansible.is_false(val2)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' has log file validation explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# community.aws.cloudtrail module variants
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "community.aws.cloudtrail")
	some task in tasks

	not ansible.has_key(task, "enable_log_file_validation")
	not ansible.has_key(task, "log_file_validation_enabled")
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' does not have log file validation enabled (missing attribute)", [ansible.task_name(task)]),
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

	tasks := ansible.tasks_with_module(content, "community.aws.cloudtrail")
	some task in tasks

	val := ansible.string_attr(task, "enable_log_file_validation")
	ansible.is_false(val)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' has log file validation explicitly disabled", [ansible.task_name(task)]),
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

	tasks := ansible.tasks_with_module(content, "community.aws.cloudtrail")
	some task in tasks

	val := ansible.string_attr(task, "log_file_validation_enabled")
	ansible.is_false(val)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' has log file validation explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
