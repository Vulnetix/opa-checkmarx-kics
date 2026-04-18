# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_missing_healthcheck

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-MISSING-HEALTHCHECK",
	"name": "Missing HEALTHCHECK Instruction",
	"description": "The HEALTHCHECK instruction tells Docker how to test a container to check that it is still working. Without a healthcheck, there is no automated way to detect if a container is in a broken state and needs to be restarted.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#healthcheck",
	"languages": ["dockerfile"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-703"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices", "monitoring"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Not scratch images
	not only_from_scratch(content)

	# No HEALTHCHECK found
	not dockerfile.has_instruction(content, "healthcheck")

	finding := {
		"rule_id": metadata.id,
		"message": "Dockerfile should contain a HEALTHCHECK instruction to enable container health monitoring",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "FROM",
	}
}

only_from_scratch(content) if {
	images := dockerfile.from_images(content)
	count(images) == 1
	lower(images[0]) == "scratch"
}
