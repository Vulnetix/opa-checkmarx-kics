# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_multiple_entrypoint_instructions_listed

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-MULTIPLE-ENTRYPOINT",
	"name": "Multiple ENTRYPOINT Instructions",
	"description": "There should be only one ENTRYPOINT instruction in a Dockerfile. Only the last ENTRYPOINT instruction will take effect, having multiple can be confusing and misleading.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#entrypoint",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-398"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Count ENTRYPOINT instructions
	entrypoint_count := count(dockerfile.dockerfile_instructions(content, "entrypoint"))
	entrypoint_count > 1

	# Get the first one for reporting
	entrypoint_insts := dockerfile.dockerfile_instructions(content, "entrypoint")
	first_entrypoint := entrypoint_insts[0]

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Multiple ENTRYPOINT instructions found (%d). Only the last one takes effect.", [entrypoint_count]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": first_entrypoint.line,
		"snippet": first_entrypoint.original,
	}
}
