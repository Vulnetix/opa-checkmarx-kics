# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_pip_no_cache

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-PIP-NO-CACHE",
	"name": "pip install Without --no-cache-dir",
	"description": "pip install should use the --no-cache-dir flag to avoid keeping cached packages in the container image. This reduces image size and prevents potential security issues from cached packages.",
	"help_uri": "https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-no-cache-dir",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-770"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "optimization", "python"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")

	# Check for pip install
	regex.match(`pip(3)?\s+(-[a-zA-Z]+\s+)*install`, lower(inst.value))

	# Should have --no-cache-dir
	not contains(lower(inst.value), "--no-cache-dir")

	finding := {
		"rule_id": metadata.id,
		"message": "pip install should use --no-cache-dir flag to reduce image size",
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
