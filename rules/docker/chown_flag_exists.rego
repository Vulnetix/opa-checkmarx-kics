# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_chown_flag_exists

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-CHOWN-FLAG",
	"name": "Chown Flag in COPY/ADD",
	"description": "The --chown flag in COPY or ADD instructions should be used carefully. Using --chown can lead to ownership issues and security concerns if not properly managed.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#copy",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some cmd_type in ["copy", "add"]
	some inst in dockerfile.dockerfile_instructions(content, cmd_type)

	# Check for --chown flag
	contains(lower(inst.value), "--chown")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s uses --chown flag. Review ownership settings for security.", [upper(cmd_type)]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
