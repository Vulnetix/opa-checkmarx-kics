# Ported from checkmarx-kics/rules/ansible/aws/s3_bucket_without_versioning
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_s3_no_versioning

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-S3-002",
	"name": "S3 bucket without versioning",
	"description": "S3 buckets should have versioning enabled to protect against accidental deletion and provide recovery capabilities.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": ["T1490"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "s3", "versioning", "backup"],
}

# Check for s3_bucket module without versioning
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "s3_bucket")
	some task in tasks

	not ansible.has_key(task, "versioning")
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket '%s' does not have versioning configured (missing attribute)", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Check for s3_bucket with versioning explicitly disabled
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "s3_bucket")
	some task in tasks

	val := ansible.string_attr(task, "versioning")
	ansible.is_false(val)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket '%s' has versioning explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# amazon.aws.s3_bucket variants
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "amazon.aws.s3_bucket")
	some task in tasks

	not ansible.has_key(task, "versioning")
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket '%s' does not have versioning configured (missing attribute)", [ansible.task_name(task)]),
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

	tasks := ansible.tasks_with_module(content, "amazon.aws.s3_bucket")
	some task in tasks

	val := ansible.string_attr(task, "versioning")
	ansible.is_false(val)
	ansible.is_present_state(task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket '%s' has versioning explicitly disabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
