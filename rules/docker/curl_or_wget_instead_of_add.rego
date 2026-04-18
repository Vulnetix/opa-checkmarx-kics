# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_curl_or_wget_instead_of_add

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-ADD-URL",
	"name": "ADD Used With URL Instead of curl/wget",
	"description": "ADD with URL should use curl or wget instead for better control, security, and to leverage layer caching. curl/wget allows specifying authentication, retries, and better handling of redirects.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-829"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "add")

	# Check for URL
	regex.match(`^https?://`, inst.value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use curl or wget instead of ADD for URL: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
