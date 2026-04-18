# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_multiple_cmd_instructions_listed

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-MULTIPLE-CMD",
	"name": "Multiple CMD Instructions",
	"description": "There should be only one CMD instruction in a Dockerfile. Only the last CMD instruction will take effect, having multiple can be confusing and misleading.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#cmd",
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

	# Count CMD instructions
	cmd_count := count(dockerfile.dockerfile_instructions(content, "cmd"))
	cmd_count > 1

	# Get the first one for reporting
	cmd_insts := dockerfile.dockerfile_instructions(content, "cmd")
	first_cmd := cmd_insts[0]

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Multiple CMD instructions found (%d). Only the last one takes effect.", [cmd_count]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": first_cmd.line,
		"snippet": first_cmd.original,
	}
}
