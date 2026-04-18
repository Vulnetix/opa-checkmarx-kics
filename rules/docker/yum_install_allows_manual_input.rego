# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_yum_install_allows_manual_input

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-YUM-NO-ASSUMEYES",
	"name": "YUM Install Without -y/--assumeyes",
	"description": "When using yum install, the -y or --assumeyes flag should be set to avoid manual input and ensure the build proceeds without user intervention.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "validation"],
}

yum_install_patterns := [
	`yum\s+(\S+\s+)*groupinstall`,
	`yum\s+(\S+\s+)*localinstall`,
	`yum\s+(\S+\s+)*install`,
]

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Has yum install
	some pattern in yum_install_patterns
	regex.match(pattern, value)

	# Missing -y/--assumeyes
	not regex.match(`yum\s+(\S+\s+)*(-y|--assumyes)\s`, value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Add -y or --assumeyes to yum install: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
