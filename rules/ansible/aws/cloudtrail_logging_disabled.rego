# Ported from checkmarx-kics/rules/ansible/aws/cloudtrail_logging_disabled
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_cloudtrail_disabled

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-LOG-001",
	"name": "CloudTrail logging disabled",
	"description": "CloudTrail should have enable_logging set to true to ensure all AWS API activity is logged.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/community/aws/cloudtrail_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": ["T1562"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "cloudtrail", "logging", "auditing"],
}

# Check for cloudtrail module with enable_logging: false
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "cloudtrail")
	some task in tasks

	# Check if enable_logging is set to false
	val := ansible.string_attr(task, "enable_logging")
	ansible.is_false(val)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' has enable_logging set to false", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# community.aws.cloudtrail module
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "community.aws.cloudtrail")
	some task in tasks

	val := ansible.string_attr(task, "enable_logging")
	ansible.is_false(val)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail '%s' has enable_logging set to false", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
