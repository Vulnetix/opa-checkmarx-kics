# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_image_version_using_latest

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-IMAGE-LATEST-TAG",
	"name": "Image Version Using 'latest'",
	"description": "Using the 'latest' tag for Docker images can lead to unpredictable builds as the image may change without warning. Always use specific version tags to ensure reproducible builds.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#understand-build-context",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices", "reproducibility"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "from")

	# Extract image name (remove AS alias if present)
	parts := regex.split(`\s+(AS|as|As|aS)\s+`, inst.value)
	image := trim_space(parts[0])

	# Check for :latest tag or implicit latest (no tag)
	endswith(lower(image), ":latest")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Image '%s' uses 'latest' tag. Use a specific version tag instead.", [image]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "from")

	# Extract image name (remove AS alias if present)
	parts := regex.split(`\s+(AS|as|As|aS)\s+`, inst.value)
	image := trim_space(parts[0])

	# No tag specified (implicit latest) but not scratch
	not contains(image, ":")
	not lower(image) == "scratch"
	not is_build_stage_alias(content, image)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Image '%s' has no tag specified (implicit 'latest'). Use a specific version tag.", [image]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

# Check if image is a build stage alias from a previous FROM ... AS ...
is_build_stage_alias(content, image) if {
	some inst in dockerfile.dockerfile_instructions(content, "from")
	parts := regex.split(`\s+(AS|as|As|aS)\s+`, inst.value)
	count(parts) >= 2
	trim_space(lower(parts[1])) == lower(image)
}
