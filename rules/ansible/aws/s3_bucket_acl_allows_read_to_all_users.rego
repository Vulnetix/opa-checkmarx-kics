# Ported from checkmarx-kics/rules/ansible/aws/s3_bucket_acl_allows_read_to_all_users
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_s3_acl_read_all_users

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-S3-001",
	"name": "S3 Bucket ACL allows read access to all users",
	"description": "S3 bucket should not allow public 'public-read' ACL permissions that grant read access to anyone.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/amazon/aws/aws_s3_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "s3", "public", "acl"],
}

findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	# Check for aws_s3 module with public-read permission
	tasks := ansible.tasks_with_module(content, "aws_s3")
	some task in tasks

	# Check if permission attribute starts with public-read
	perm := ansible.string_attr(task, "permission")
	startswith(lower(perm), "public-read")

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket '%s' configured with ACL that grants read access to all users (permission: %s)", [ansible.task_name(task), perm]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Also check amazon.aws.aws_s3 module
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "amazon.aws.aws_s3")
	some task in tasks

	perm := ansible.string_attr(task, "permission")
	startswith(lower(perm), "public-read")

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket '%s' configured with ACL that grants read access to all users (permission: %s)", [ansible.task_name(task), perm]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
