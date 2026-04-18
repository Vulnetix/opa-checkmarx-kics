# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_add_instead_of_copy

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-ADD-INSTEAD-OF-COPY",
	"name": "Add Instead of Copy",
	"description": "The COPY instruction copies files from the local host. ADD instruction could copy files from remote URLs and extract TAR files. COPY is preferred over ADD for local files to avoid accidental extraction of archives or remote downloads.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-829"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "add")

	# Not a tar file (which needs extraction)
	not is_tar_file(inst.value)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use COPY instead of ADD for local files: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

is_tar_file(value) if {
	contains(lower(value), ".tar")
}

is_tar_file(value) if {
	contains(lower(value), ".tar.gz")
}

is_tar_file(value) if {
	contains(lower(value), ".tgz")
}

is_tar_file(value) if {
	contains(lower(value), ".bz2")
}
