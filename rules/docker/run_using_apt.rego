# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_run_using_apt

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-APT-NOT-APT-GET",
	"name": "Run Using apt Instead of apt-get",
	"description": "The 'apt' command is designed for interactive use and should not be used in Dockerfiles. Use 'apt-get' instead which is designed for scripting and provides stable output suitable for automation.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Check for standalone apt (not apt-get, not aptitude)
	regex.match(`(^|[;&|]|\|\||&&|\s)apt\s+`, value)
	not contains(value, "apt-get")
	not contains(value, "aptitude")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use 'apt-get' instead of 'apt' in scripts: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
