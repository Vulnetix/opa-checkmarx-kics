# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_exposing_port_22

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-EXPOSE-PORT-22",
	"name": "Exposing Port 22 (SSH)",
	"description": "Exposing port 22 (SSH) in a Dockerfile can provide an attacker with an additional attack surface to target the container. SSH access should not be exposed in containerized environments; use docker exec for debugging instead.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#expose",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287"],
	"capec": [],
	"attack_technique": ["T1021.004"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "security", "network"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "expose")

	# Check if port 22 is exposed
	port_str := regex.split(`\s+`, inst.value)[0]
	to_number(port_str) == 22

	finding := {
		"rule_id": metadata.id,
		"message": "Port 22 (SSH) should not be exposed in Dockerfile. Use 'docker exec' instead.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
