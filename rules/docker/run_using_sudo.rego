# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_run_using_sudo

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-RUN-USING-SUDO",
	"name": "Run Using Sudo",
	"description": "sudo allows users to run programs with elevated privileges. It is not necessary to use sudo in Docker containers as the user can be set to root or another user with the appropriate privileges. Running commands with sudo inside a container can lead to security vulnerabilities and should be avoided.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#run",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "security", "privilege-escalation"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")

	# Check for sudo in the command
	regex.match(`(^|\s|&&|;|\|)sudo(\s|$)`, lower(inst.value))

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RUN instruction should not use sudo: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
