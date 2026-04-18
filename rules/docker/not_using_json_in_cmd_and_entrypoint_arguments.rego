# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_not_using_json_in_cmd_and_entrypoint_arguments

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-NO-JSON-FORMAT",
	"name": "CMD and ENTRYPOINT Not in JSON Format",
	"description": "CMD and ENTRYPOINT instructions should use JSON array format instead of shell format. JSON format ensures the executable runs as PID 1 and signals are properly handled.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#cmd",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices", "signal-handling"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some cmd_type in ["cmd", "entrypoint"]
	some inst in dockerfile.dockerfile_instructions(content, cmd_type)

	# Check if not JSON array format
	not regex.match(`^\s*\[`, inst.value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s should use JSON array format [\"executable\", \"param1\", ...]", [upper(cmd_type)]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
