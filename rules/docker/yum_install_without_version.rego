# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_yum_install_without_version

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-YUM-NO-VERSION",
	"name": "YUM Install Without Version",
	"description": "When installing packages with yum, the package version should be specified to ensure reproducible builds and prevent unexpected updates.",
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

	# Has yum install
	regex.match(`(?i)yum\s+(\S+\s+)*install`, value)

	# No version specified
	not dockerfile.with_version(value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Specify package version in yum install with 'name-version-release' format: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
