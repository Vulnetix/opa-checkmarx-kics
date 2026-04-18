# Adapted from https://github.com/Checkmarx/kics
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.kics_docker_unix_ports_out_of_range

import rego.v1

import data.vulnetix.kics.dockerfile

metadata := {
	"id": "KICS-DOCKER-PORTS-OUT-OF-RANGE",
	"name": "Unix Ports Out of Range",
	"description": "Exposing an incorrect or unnecessarily large port range can increase the attack surface of the container. Valid TCP/UDP ports range from 0 to 65535. Ports outside this range are invalid.",
	"help_uri": "https://docs.docker.com/engine/reference/builder/#expose",
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

	some inst in dockerfile.dockerfile_instructions(content, "expose")

	# Extract port number
	port_str := regex.split(`\s+`, inst.value)[0]
	port := to_number(port_str)

	# Check if port is out of valid range (0-65535)
	port > 65535

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Port %d is out of valid range (0-65535)", [port]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
