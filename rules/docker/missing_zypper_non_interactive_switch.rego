# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_missing_zypper_non_interactive_switch

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-ZYPPER-NO-YES",
	"name": "Zypper Without Non-Interactive Switch",
	"description": "When using zypper in Docker, the -y or --no-confirm flag should be set to avoid manual input and ensure the build proceeds without user intervention.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "validation"],
}

zypper_commands := {"zypper in", "zypper install", "zypper remove", "zypper rm", "zypper source-install", "zypper si", "zypper patch"}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Check for zypper usage
	some cmd in zypper_commands
	contains(value, cmd)

	# Check for missing -y/--no-confirm
	not regex.match(`zypper\s+(\S+\s+)*(-y|--no-confirm)\s`, value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Add -y or --no-confirm to zypper command: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
