# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_missing_flag_from_dnf_install

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-DNF-NO-ASSUMEYES",
	"name": "DNF Install Without -y/--assumeyes",
	"description": "When using dnf install, the -y or --assumeyes flag should be set to avoid manual input and ensure the build proceeds without user intervention.",
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

dnf_install_commands := {"dnf install", "dnf groupinstall", "dnf localinstall", "dnf reinstall", "dnf in", "dnf rei"}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Check for dnf install commands
	some cmd in dnf_install_commands
	contains(value, cmd)

	# Check for missing -y/--assumeyes
	not regex.match(`dnf\s+(\S+\s+)*(-y|--assumeyes)\s`, value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Add -y or --assumeyes to dnf install: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
