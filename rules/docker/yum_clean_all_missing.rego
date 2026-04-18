# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_yum_clean_all_missing

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-YUM-NO-CLEAN",
	"name": "YUM Install Without Clean",
	"description": "After installing packages with yum, the 'yum clean all' command should be run to remove cached data and reduce image size.",
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

	# Missing clean all
	not contains(value, "yum clean all")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Run 'yum clean all' after yum install to reduce image size: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
