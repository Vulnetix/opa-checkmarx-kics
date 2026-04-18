# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_maintainer_instruction_being_used

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-MAINTAINER-DEPRECATED",
	"name": "MAINTAINER Instruction Deprecated",
	"description": "The MAINTAINER instruction is deprecated. Use LABEL maintainer=... instead to specify the author of the Docker image.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#maintainer-deprecated",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-1109"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "deprecated"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "maintainer")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MAINTAINER is deprecated. Use LABEL maintainer='%s' instead.", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
