# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_multiple_run_add_copy_instructions_listed

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-COMBINE-LAYERS",
	"name": "Multiple RUN/ADD/COPY Instructions Can Be Combined",
	"description": "Multiple consecutive RUN, ADD, or COPY instructions that target the same directory or are logically related should be combined into a single instruction to reduce the number of layers and image size.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#minimize-the-number-of-layers",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices", "image-size"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Check for multiple consecutive RUN instructions
	lines := split(content, "\n")
	some i, j
	i < j
	j == i + 1

	# Line i is a RUN
	line_i := trim_space(lines[i])
	startswith(upper(line_i), "RUN ")

	# Line j is also a RUN
	line_j := trim_space(lines[j])
	startswith(upper(line_j), "RUN ")

	# Not a continuation
	not endswith(line_i, "\\")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Consider combining consecutive RUN instructions to reduce layers (lines %d and %d)", [i + 1, j + 1]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": i + 1,
		"snippet": line_i,
	}
}
