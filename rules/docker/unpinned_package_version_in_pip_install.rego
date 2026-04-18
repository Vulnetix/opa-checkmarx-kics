# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_unpinned_package_version_in_pip_install

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-PIP-NO-VERSION",
	"name": "Pip Install Without Version Pinning",
	"description": "When installing packages with pip, the version should be specified to ensure reproducible builds. Use the format 'package==version' to pin the exact version.",
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
	value := inst.value

	# Check for pip install
	regex.match(`(?i)pip\S*\s+\S*install`, value)

	# Check for missing version
	not dockerfile.with_version(value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Pin package versions with 'pip install package==version': %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
