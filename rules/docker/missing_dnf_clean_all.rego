# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_missing_dnf_clean_all

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-DNF-NO-CLEAN",
	"name": "Missing DNF Clean All",
	"description": "After installing packages with dnf, the command 'dnf clean all' should be run to remove cached data and reduce image size.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-459"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices", "image-size"],
}

dnf_install_patterns := [
	`dnf\s+install`,
	`dnf\s+in\s`,
	`dnf\s+reinstall`,
	`dnf\s+rei\s`,
	`dnf\s+install-n`,
	`dnf\s+install-na`,
	`dnf\s+install-nevra`,
]

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Check for dnf install
	some pattern in dnf_install_patterns
	regex.match(pattern, value)

	# Check for missing clean
	not contains(value, "dnf clean")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Run 'dnf clean all' after dnf install to reduce image size: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
