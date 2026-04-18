# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_missing_zypper_clean

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-ZYPPER-NO-CLEAN",
	"name": "Missing Zypper Clean",
	"description": "After using zypper commands (install, remove, etc.), the 'zypper clean' command should be run to remove cached data and reduce image size.",
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

zypper_commands := {"zypper in", "zypper install", "zypper remove", "zypper rm", "zypper source-install", "zypper si", "zypper patch"}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := lower(inst.value)

	# Check for zypper usage
	some cmd in zypper_commands
	contains(value, cmd)

	# Check for missing clean
	not contains(value, "zypper clean")
	not contains(value, "zypper cc")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Run 'zypper clean' after zypper usage to reduce image size: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
