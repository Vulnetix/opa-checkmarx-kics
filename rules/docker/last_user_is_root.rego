# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_last_user_is_root

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-LAST-USER-ROOT",
	"name": "Last User is Root",
	"description": "The last USER instruction in the Dockerfile should not be 'root'. Running containers as root violates the principle of least privilege and increases the attack surface if the container is compromised.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "security", "privilege"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Check if last user is root
	dockerfile.last_user_is_root(content)

	some inst in dockerfile.dockerfile_instructions(content, "user")
	lower(inst.value) == "root"

	finding := {
		"rule_id": metadata.id,
		"message": "Last USER instruction is root. Use a less privileged user for the final stage.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
