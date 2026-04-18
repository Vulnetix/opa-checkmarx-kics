# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_update_instruction_alone

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-UPDATE-ALONE",
	"name": "Update Instruction Alone",
	"description": "Package manager update instructions should not be used alone. Combine update with install in the same RUN instruction to prevent caching the update layer, and then clean up in the same layer.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-919"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "caching", "security"],
}

# Update commands that should be combined with install
update_patterns := [
	`apt-get\s+update`,
	`apt\s+update`,
	`apk\s+update`,
	`yum\s+update`,
	`dnf\s+update`,
	`zypper\s+refresh`,
]

install_patterns := [
	`apt-get\s+install`,
	`apt\s+install`,
	`apk\s+add`,
	`yum\s+install`,
	`dnf\s+install`,
	`zypper\s+install`,
]

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Has update command
	some update_pat in update_patterns
	regex.match(update_pat, value)

	# No install command in same RUN
	some install_pat in install_patterns
	not regex.match(install_pat, value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Combine update with install in the same RUN instruction to prevent caching stale package lists: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
