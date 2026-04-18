# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_image_version_not_explicit

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-FROM-NO-VERSION",
	"name": "Image Version Not Explicit",
	"description": "FROM instruction should specify an explicit image version/tag rather than using the implicit 'latest' tag. Failing to specify a version can lead to unexpected changes in the base image when rebuilt.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "supply-chain", "reproducibility"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "from")

	# Skip scratch
	not lower(inst.value) == "scratch"

	# Check if no version is specified (no colon or colon followed by nothing before AS)
	value := inst.value
	parts := regex.split(`(?i)\s+AS\s+`, value)
	image := trim_space(parts[0])
	not contains(image, ":")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("FROM image should specify explicit version tag: %s", [image]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
