# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_apt_get_not_avoiding_additional_packages

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-APT-NO-RECOMMENDS",
	"name": "APT Install Without --no-install-recommends",
	"description": "The 'apt-get install' command should use '--no-install-recommends' flag to avoid installing unnecessary recommended packages. This reduces image size and attack surface.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices", "image-size"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")

	# Check for apt-get install without --no-install-recommends
	value := lower(inst.value)
	regex.match(`apt-get\s+(-[-\w]+\s+)*install`, value)
	not contains(value, "--no-install-recommends")
	not contains(value, "apt::install-recommends=false")

	finding := {
		"rule_id": metadata.id,
		"message": "Use 'apt-get install' with '--no-install-recommends' flag to reduce dependencies",
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
