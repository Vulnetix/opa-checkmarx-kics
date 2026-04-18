# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_run_command_cd_instead_of_workdir

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-CD-INSTEAD-OF-WORKDIR",
	"name": "RUN CD Instead of WORKDIR",
	"description": "Using 'cd' in RUN commands to change directories is not recommended. Use WORKDIR instruction instead for better readability and to set the working directory for subsequent instructions.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Check for cd command (standalone cd or cd after && or ;)
	regex.match(`(^|[;&|]|\|\||&&)\s*cd\s+`, value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use WORKDIR instruction instead of 'cd' in RUN: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
