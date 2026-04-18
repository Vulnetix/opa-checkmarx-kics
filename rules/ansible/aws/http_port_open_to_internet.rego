# Ported from checkmarx-kics/rules/ansible/aws/http_port_open_to_internet
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_http_port_open

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-SEC-001",
	"name": "HTTP port (80) open to internet",
	"description": "EC2 security group should not allow unrestricted inbound HTTP traffic (port 80) from the internet (0.0.0.0/0).",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "ec2", "security-group", "http", "port-80"],
}

# Check for ec2_group module with port 80 open to 0.0.0.0/0
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "ec2_group")
	some task in tasks

	# Check for cidr_ip: 0.0.0.0/0 in the task
	ansible.has_unrestricted_cidr(task)

	# Check if rule includes port 80
	ansible.has_port(task, 80)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security group '%s' allows unrestricted HTTP (port 80) access from the internet", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Also check amazon.aws.ec2_group module
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "amazon.aws.ec2_group")
	some task in tasks

	ansible.has_unrestricted_cidr(task)
	ansible.has_port(task, 80)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security group '%s' allows unrestricted HTTP (port 80) access from the internet", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
