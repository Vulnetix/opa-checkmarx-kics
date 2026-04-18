# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_using_platform_with_from

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-FROM-PLATFORM",
	"name": "FROM With --platform Flag",
	"description": "Using the --platform flag in FROM instructions can lead to non-portable Dockerfiles. The platform should be determined by the build environment rather than hardcoded.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#from",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "portability"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "from")

	# Check for --platform flag
	contains(lower(inst.value), "--platform")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Avoid --platform flag in FROM for better portability: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
