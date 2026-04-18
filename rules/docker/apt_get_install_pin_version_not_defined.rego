# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_apt_get_install_pin_version

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-APT-GET-NO-VERSION",
	"name": "apt-get install Without Version Pinning",
	"description": "Using apt-get install without specifying a version allows installation of arbitrary package versions. Always pin versions to ensure reproducible builds and prevent unexpected changes.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices", "reproducibility"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")

	# Check for apt-get install
	contains(lower(inst.value), "apt-get")
	contains(lower(inst.value), "install")

	# Extract packages from command
	cmd := inst.value
	apt_get_match := regex.find_all_string_submatch_n(`apt-get\s+(-[a-zA-Z]+\s+)*install\s+(.+)`, cmd, 1)[0]
	packages_str := apt_get_match[count(apt_get_match) - 1]

	# Split packages
	packages := regex.split(`\s+`, trim_space(packages_str))

	# Check each package for version pinning
	some pkg in packages
	pkg != ""
	not is_flag(pkg)
	not dockerfile.with_version(pkg)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Package '%s' in apt-get install should have version pinned (use '=' or ':' to specify version)", [pkg]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

is_flag(str) if startswith(str, "-")
is_flag(str) if startswith(str, "--")
