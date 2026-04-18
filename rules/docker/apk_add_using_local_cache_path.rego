# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_apk_add_using_local_cache_path

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-APK-NO-CACHE",
	"name": "APK Add Without No-Cache",
	"description": "The 'apk add' command should use '--no-cache' flag to avoid caching the index locally and reduce image size. This prevents unnecessary layers in the Docker image.",
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

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")

	# Check for apk add without --no-cache
	cmds := dockerfile.get_commands(inst.value)
	some cmd in cmds
	trim_cmd := trim_space(cmd)
	startswith(lower(trim_cmd), "apk ")
	contains(trim_cmd, " add ")
	not dockerfile.has_no_cache_flag(trim_cmd)

	finding := {
		"rule_id": metadata.id,
		"message": "Use 'apk add' with '--no-cache' flag to reduce image size",
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
