# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_missing_user_instruction

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-MISSING-USER",
	"name": "Missing USER Instruction",
	"description": "A USER instruction in a Dockerfile specifies the user that the container should run as. Without a USER instruction, containers run as root by default which violates the principle of least privilege and can lead to security vulnerabilities if the container is compromised.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "security", "least-privilege"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Exclude scratch images which don't need a user
	not all_from_scratch(content)

	# Check if no USER instruction exists
	not dockerfile.has_user(content)

	finding := {
		"rule_id": metadata.id,
		"message": "Dockerfile does not contain any USER instruction. Container will run as root.",
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": "FROM",
	}
}

all_from_scratch(content) if {
	images := dockerfile.from_images(content)
	count(images) == 1
	lower(images[0]) == "scratch"
}
