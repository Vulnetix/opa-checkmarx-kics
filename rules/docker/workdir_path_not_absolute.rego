# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_workdir_path_not_absolute

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-WORKDIR-RELATIVE",
	"name": "WORKDIR Path Not Absolute",
	"description": "The WORKDIR instruction should use absolute paths. Relative paths can lead to unpredictable behavior depending on the base image PATH configuration.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#workdir",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "validation"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "workdir")
	value := inst.value

	# Check if path is relative (not absolute)
	not dockerfile.is_absolute_path(value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("WORKDIR should use an absolute path: %s", [value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
