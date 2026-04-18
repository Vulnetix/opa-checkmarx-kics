# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_copy_with_more_than_two_arguments_not_ending_with_slash

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-COPY-ARGS-SLASH",
	"name": "COPY With Multiple Arguments Missing Trailing Slash",
	"description": "When COPY command has more than two arguments, the last argument should end with a trailing slash to indicate that it is a directory. Without this, Docker may interpret the destination incorrectly.",
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
	"tags": ["docker", "validation"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "copy")

	# Parse arguments - removing leading flags like --from=
	value := regex.replace(inst.value, `--[a-zA-Z-]+\s+\S+\s*`, "")
	value_trimmed := trim_space(value)

	# Split by spaces to get arguments
	args := regex.split(`\s+`, value_trimmed)
	count(args) > 2

	# Check last argument doesn't end with /
	last_arg := args[count(args) - 1]
	not endswith(last_arg, "/")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("COPY with multiple arguments should end with trailing slash: %s", [last_arg]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
