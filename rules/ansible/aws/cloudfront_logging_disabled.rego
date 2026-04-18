# Ported from checkmarx-kics/rules/ansible/aws/cloudfront_logging_disabled
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_cloudfront_logging_disabled

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-CF-001",
	"name": "CloudFront distribution logging disabled",
	"description": "CloudFront distributions should have logging enabled to track access patterns and enable security auditing.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": ["T1562"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "cloudfront", "cdn", "logging"],
}

# Check for missing logging configuration
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "cloudfront_distribution")
	some task in tasks

	not ansible.has_key(task, "logging")
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution '%s' does not have logging configured", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Check for disabled logging
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "cloudfront_distribution")
	some task in tasks

	# logging.enabled is false or not set
	logging_enabled := ansible.string_attr(task, "logging.enabled")
	ansible.is_false(logging_enabled)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution '%s' has logging disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# community.aws.cloudfront_distribution variants
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "community.aws.cloudfront_distribution")
	some task in tasks

	not ansible.has_key(task, "logging")
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution '%s' does not have logging configured", [ansible.task_name(task)]),
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

	tasks := ansible.tasks_with_module(content, "community.aws.cloudfront_distribution")
	some task in tasks

	logging_enabled := ansible.string_attr(task, "logging.enabled")
	ansible.is_false(logging_enabled)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution '%s' has logging disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
