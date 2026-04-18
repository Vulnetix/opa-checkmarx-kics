# Ported from checkmarx-kics/rules/ansible/aws/rds_with_backup_disabled
# Original: https://github.com/Checkmarx/kics

package vulnetix.rules.kics_ansible_rds_no_backup

import rego.v1

import data.vulnetix.kics.ansible

metadata := {
	"id": "KICS-ANSIBLE-AWS-BCK-001",
	"name": "RDS instance backup disabled",
	"description": "RDS instance should have automated backups enabled with backup_retention_period greater than 0.",
	"help_uri": "https://docs.ansible.com/ansible/latest/collections/community/aws/rds_instance_module.html",
	"languages": ["ansible", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ansible", "aws", "rds", "backup", "resilience"],
}

# Check for rds_instance module with backup_retention_period: 0
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "rds_instance")
	some task in tasks

	# Check if backup_retention_period is 0
	val := ansible.string_attr(task, "backup_retention_period")
	val == "0"

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS instance '%s' has backup_retention_period set to 0 (automated backups disabled)", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}

# Community AWS module variant
findings contains finding if {
	some path, content in input.file_contents
	ansible.is_ansible_yaml(path)

	tasks := ansible.tasks_with_module(content, "community.aws.rds_instance")
	some task in tasks

	val := ansible.string_attr(task, "backup_retention_period")
	val == "0"

	line := ansible.task_start_line(content, task)
	snippet := ansible.snippet_around_line(content, line)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS instance '%s' has backup_retention_period set to 0 (automated backups disabled)", [ansible.task_name(task)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": snippet,
	}
}
