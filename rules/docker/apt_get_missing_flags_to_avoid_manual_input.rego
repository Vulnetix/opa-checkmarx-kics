# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_apt_get_missing_yes_flag

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-APT-GET-NO-YES",
	"name": "apt-get install Missing -y/-qq Flag",
	"description": "apt-get install commands should use the -y or -qq flag to avoid interactive prompts during container build. Without these flags, the build may hang waiting for user input.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-834"],
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

	# Check for apt-get install
	contains(lower(inst.value), "apt-get")
	contains(lower(inst.value), "install")

	# Should have -y, --yes, or -qq flag
	not has_auto_confirm_flag(inst.value)

	finding := {
		"rule_id": metadata.id,
		"message": "apt-get install should use -y, --yes, or -qq flag to avoid interactive prompts",
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

has_auto_confirm_flag(cmd) if {
	regex.match(`(^|\s)-y(\s|$)`, cmd)
}

has_auto_confirm_flag(cmd) if {
	regex.match(`(^|\s)--yes(\s|$)`, cmd)
}

has_auto_confirm_flag(cmd) if {
	regex.match(`(^|\s)-qq(\s|$)`, cmd)
}
