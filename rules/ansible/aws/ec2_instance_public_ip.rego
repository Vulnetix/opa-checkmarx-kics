# Ported from checkmarx-kics/rules/ansible/aws/ec2_instance_has_public_ip
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_ec2_public_ip

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-NET-001",
	"name": "EC2 instance has public IP",
	"description": "EC2 instance should not be assigned a public IP address directly. Use NAT Gateway or ALB for public access.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "ec2", "public-ip", "networking"],
}

# Check for ec2 module with assign_public_ip: true
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "ec2")
	some task in tasks

	# Check if assign_public_ip is true
	not regex.match(`network_interfaces:`, task)
	val := ansible.string_attr(task, "assign_public_ip")
	ansible.is_true(val)

	not regex.match(`state:\s*absent`, task)
	not regex.match(`state:\s*list`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EC2 instance '%s' has assign_public_ip enabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# ec2_launch_template with associate_public_ip_address
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "ec2_launch_template")
	some task in tasks

	# Match network_interfaces.associate_public_ip_address: true
	regex.match(`(?m)associate_public_ip_address:\s*(yes|true|True)`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EC2 launch template '%s' has associate_public_ip_address enabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# ec2_instance module with network.assign_public_ip
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "ec2_instance")
	some task in tasks

	# Match network.assign_public_ip: true
	regex.match(`(?m)assign_public_ip:\s*(yes|true|True)`, task)

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EC2 instance '%s' has network.assign_public_ip enabled", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
