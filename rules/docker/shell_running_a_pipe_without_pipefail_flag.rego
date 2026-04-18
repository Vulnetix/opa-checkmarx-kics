# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_shell_running_a_pipe_without_pipefail_flag

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-PIPE-NO-FAIL",
	"name": "Shell Pipe Without pipefail Flag",
	"description": "When using pipes in shell commands with bash, the 'pipefail' option should be set to ensure that failures in any command of a pipeline are detected. Without pipefail, only the exit status of the last command is considered.",
	"help_uri": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "error-handling"],
}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	# Check for SHELL instruction setting pipefail
	some inst in dockerfile.dockerfile_instructions(content, "run")
	value := inst.value

	# Has pipe
	contains(value, "|")

	# Uses bash or similar shell
	regex.match(`\b(bash|sh|zsh)\b`, lower(value))

	# No pipefail set
	not contains(value, "pipefail")

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use 'set -o pipefail' when using pipes in shell commands: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
