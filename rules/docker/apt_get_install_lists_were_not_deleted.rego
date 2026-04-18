# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_apt_get_no_cleanup

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-APT-GET-NO-CLEANUP",
	"name": "apt-get install Lists Not Deleted",
	"description": "After running apt-get install, the package lists should be cleaned up to reduce image size. Use 'rm -rf /var/lib/apt/lists/*' at the end of the RUN command to remove cached package lists.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-770"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "optimization", "size"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")

	# Check for apt-get install
	contains(lower(inst.value), "apt-get")
	contains(lower(inst.value), "install")

	# Check that /var/lib/apt/lists is not being cleaned
	not cleans_apt_lists(inst.value)

	finding := {
		"rule_id": metadata.id,
		"message": "apt-get install should clean up package lists with 'rm -rf /var/lib/apt/lists/*'",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

cleans_apt_lists(cmd) if {
	contains(lower(cmd), "/var/lib/apt/lists")
	contains(lower(cmd), "rm")
}
