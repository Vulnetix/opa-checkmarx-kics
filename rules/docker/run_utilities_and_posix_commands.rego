# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_run_utilities_and_posix_commands

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-DANGEROUS-COMMANDS",
	"name": "Dangerous POSIX Commands in RUN",
	"description": "Certain POSIX commands and utilities should not be executed in Docker containers as they can expose sensitive system information or be used for debugging/exploitation. These include ps, shutdown, service, ifconfig, etc.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "security"],
}

# Dangerous commands that shouldn't be in containers
dangerous_commands := {"ps", "shutdown", "service", "free", "top", "kill", "mount", "ifconfig", "nano", "vim", "vi"}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Split commands by separators
	cmds := dockerfile.get_commands(value)
	some cmd in cmds
	trim_cmd := trim_space(cmd)

	some dangerous in dangerous_commands
	regex.match(sprintf(`^%s\b`, [dangerous]), trim_cmd)

	# Skip if part of install command
	not contains(trim_cmd, "install")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Avoid using '%s' command in Docker containers", [dangerous]),
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
