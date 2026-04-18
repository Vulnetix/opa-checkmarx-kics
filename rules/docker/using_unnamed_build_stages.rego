# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_using_unnamed_build_stages

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-COPY-FROM-NUMBER",
	"name": "COPY --from Using Numeric Index",
	"description": "COPY --from should reference a named stage (alias) rather than a numeric index. Using numeric indices makes the Dockerfile fragile as adding/removing stages can break the reference.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#copy",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
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

	some inst in dockerfile.dockerfile_instructions(content, "copy")
	value := inst.value

	# Check for --from with numeric reference
	regex.match(`(?i)--from=\d+`, value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use named stage aliases instead of numeric indices in COPY --from: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
