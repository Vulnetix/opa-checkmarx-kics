# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_copy_from_references_current_from_alias

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-COPY-FROM-SELF",
	"name": "COPY --from References Current FROM Alias",
	"description": "The COPY --from instruction should not reference the current FROM alias. This creates a circular dependency that will fail the build.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#copy",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-829"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "error"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Get all FROM images with their aliases
	from_insts := dockerfile.dockerfile_instructions(content, "from")
	aliases := [parts[1] |
		some inst in from_insts
		value := inst.value
		regex.match(`(?i)\s+AS\s+`, value)
		parts := regex.split(`(?i)\s+AS\s+`, value)
		count(parts) > 1
	]

	some copy_inst in dockerfile.dockerfile_instructions(content, "copy")
	value := copy_inst.value

	# Check for --from=
	regex.match(`(?i)--from=([^\\s]+)`, value)
	parts := regex.split(`(?i)--from=`, value)
	count(parts) > 1
	ref_parts := regex.split(`\s+`, parts[1])
	ref_alias := trim_space(ref_parts[0])

	# Check if referencing itself (alias in the list)
	ref_alias in aliases

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("COPY --from references current FROM alias '%s' which creates a circular dependency", [ref_alias]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": copy_inst.line,
		"snippet": copy_inst.original,
	}
}
