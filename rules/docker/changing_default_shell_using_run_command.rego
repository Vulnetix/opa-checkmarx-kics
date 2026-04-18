# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_changing_default_shell_using_run_command

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-SHELL-RUN",
	"name": "Changing Default Shell Using RUN",
	"description": "Changing the default shell using RUN instruction instead of SHELL instruction is not recommended. Use the SHELL instruction to set the default shell for subsequent RUN, CMD, and ENTRYPOINT instructions.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#shell",
	"languages": ["dockerfile"],
	"severity": "info",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-398"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practices"],
}

shell_commands := {"mv", "chsh", "usermod", "ln"}

shell_paths := {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ash", "/bin/csh", "/bin/ksh", "/bin/dash", "/bin/fish", "/bin/tcsh", "/bin/tmux", "/bin/rbash", "/usr/bin/zsh", "/etc/shells", "powershell", "/usr/bin/powershell"}

findings contains finding if {
	some path, content in input.file_contents
	dockerfile.is_dockerfile_path(path)

	some inst in dockerfile.dockerfile_instructions(content, "run")

	# Check for shell change commands
	value := lower(inst.value)
	parts := regex.split(`\s+`, value)
	count(parts) >= 1
	shell_commands[trim_space(parts[0])]

	some shell_path in shell_paths
	contains(value, shell_path)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use SHELL instruction instead of RUN to change default shell: %s", [inst.value]),
		"artifact_uri": path,
		"severity": "info",
		"level": "note",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
