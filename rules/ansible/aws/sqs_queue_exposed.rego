# Ported from checkmarx-kics/rules/ansible/aws/sqs_queue_exposed
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_sqs_queue_exposed

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-SQS-001",
	"name": "SQS queue exposed to public",
	"description": "SQS queue policy should not allow unrestricted access from the internet ('Principal': '*').",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue",
	"languages": ["ansible", "yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "sqs", "queue", "public-access"],
}

# Check for SQS queue with Principal: * in policy
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "sqs_queue")
	some task in tasks

	# Check for policy containing Principal: *
	policy := ansible.policy_text(task)
	count(policy) > 0
	regex.match(`"Principal"\s*:\s*"\*"`, policy)

	not regex.match(`state:\s*absent`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQS queue '%s' has policy with Principal set to '*' (publicly accessible)", [ansible.task_name(task)]),
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

	tasks := ansible.tasks_with_module(content, "community.aws.sqs_queue")
	some task in tasks

	policy := ansible.policy_text(task)
	count(policy) > 0
	regex.match(`"Principal"\s*:\s*"\*"`, policy)

	not regex.match(`state:\s*absent`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQS queue '%s' has policy with Principal set to '*' (publicly accessible)", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
