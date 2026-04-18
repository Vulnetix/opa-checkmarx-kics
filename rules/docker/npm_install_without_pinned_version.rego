# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_npm_install_without_pinned_version

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-NPM-NO-PIN",
	"name": "NPM Install Without Pinned Version",
	"description": "When using npm install, the package version should be pinned to ensure reproducible builds. Using specific versions or exact references prevents supply chain attacks.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
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

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Check for npm install/add
	regex.match(`npm\s+(install|i|add)\s`, value)

	# Not using exact version pinning
	not has_pinned_version(value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use pinned versions or package-lock.json with npm install: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

# npm ci and --frozen-lockfile are ok
has_pinned_version(value) if {
	contains(value, "npm ci")
}

has_pinned_version(value) if {
	contains(value, "--frozen-lockfile")
}

has_pinned_version(value) if {
	contains(value, "package-lock.json")
}
