# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_same_alias_in_different_froms

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-DUPLICATE-ALIAS",
	"name": "Same Alias in Different FROMs",
	"description": "Different FROM instructions should not use the same alias. Aliases must be unique within a Dockerfile to properly reference different build stages.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#from",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "error"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Get all FROM instructions
	from_insts := dockerfile.dockerfile_instructions(content, "from")

	# Extract aliases
	aliases := [alias |
		some inst in from_insts
		value := inst.value
		regex.match(`(?i)\s+AS\s+`, value)
		parts := regex.split(`(?i)\s+AS\s+`, value)
		count(parts) > 1
		alias := upper(trim_space(parts[1]))
	]

	# Check for duplicate aliases
	count(aliases) > count({a | some a in aliases})

	# Get the duplicate
	some inst in from_insts

	finding := {
		"rule_id": metadata.id,
		"message": "Duplicate FROM alias found. Each stage must have a unique alias.",
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
