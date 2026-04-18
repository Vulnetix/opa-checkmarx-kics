# Dockerfile helper library for KICS rules ported to Vulnetix schema.
# Imported from checkmarx-kics assets/libraries/dockerfile.rego

package vulnetix.kics.dockerfile

import rego.v1

# is_dockerfile_path checks if the path is a Dockerfile
is_dockerfile_path(path) if endswith(lower(path), "dockerfile")

is_dockerfile_path(path) if endswith(lower(path), ".dockerfile")

# _normalised joins Dockerfile line continuations (\<newline>) into single lines
_normalised(content) := replace(content, "\\\n", " ")

# dockerfile_instructions finds instructions of a specific type (e.g., "run", "from", "copy")
# Returns array of instruction objects with cmd and value keys
dockerfile_instructions(content, instruction_type) := out if {
	lines := split(_normalised(content), "\n")
	out := [inst |
		some line in lines
		trimmed := trim_space(line)
		trimmed != ""
		not startswith(trimmed, "#")
		parts := regex.split(`\s+`, trimmed)
		count(parts) >= 1
		cmd := lower(parts[0])
		cmd == lower(instruction_type)
		value := substring(trimmed, count(parts[0]), -1)
		inst := {
			"cmd": cmd,
			"value": trim_space(value),
			"original": trimmed,
			"line": _line_number(content, trimmed),
		}
	]
}

# Get all instructions regardless of type
all_instructions(content) := out if {
	lines := split(_normalised(content), "\n")
	out := [inst |
		some line in lines
		trimmed := trim_space(line)
		trimmed != ""
		not startswith(trimmed, "#")
		parts := regex.split(`\s+`, trimmed)
		count(parts) >= 1
		cmd := lower(parts[0])
		value := substring(trimmed, count(parts[0]), -1)
		inst := {
			"cmd": cmd,
			"value": trim_space(value),
			"original": trimmed,
			"line": _line_number(content, trimmed),
		}
	]
}

# instruction_args extracts arguments from an instruction value (handles JSON array format)
instruction_args(instruction) := args if {
	value := instruction.value
	# Check for JSON array format ["arg1", "arg2"]
	regex.match(`^\[.*\]$`, trim_space(value))
	# Parse JSON array
	parsed := json.unmarshal(value)
	args := parsed
} else = args if {
	# Regular shell format - split by spaces
	value := instruction.value
	args := regex.split(`\s+`, trim_space(value))
}

# Helper to get line number (approximate)
_line_number(content, line_content) := 1 if {
	true
} else = line_num if {
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _line_substr(line_content))
	line_num := i + 1
}

_line_substr(content) := content if {
	count(content) <= 40
} else = substring(content, 0, 40)

# get_commands splits commands by && or ;
get_commands(commands) := split(commands, "&&")
get_commands(commands) := split(commands, "; ")

# has_instruction checks if instruction exists
has_instruction(content, instruction_type) if {
	some inst in all_instructions(content)
	inst.cmd == lower(instruction_type)
}

# from_images returns all FROM image references (without alias)
from_images(content) := out if {
	out := [image |
		some inst in dockerfile_instructions(content, "from")
		# Split on AS to remove alias
		parts := regex.split(`\s+(AS|as|As|aS)\s+`, inst.value)
		image := trim_space(parts[0])
	]
}

# from_aliases returns all FROM alias definitions
from_aliases(content) := out if {
	out := [alias |
		some inst in dockerfile_instructions(content, "from")
		value := inst.value
		regex.match(`(?i)\s+AS\s+`, value)
		parts := regex.split(`(?i)\s+AS\s+`, value)
		count(parts) > 1
		alias := trim_space(parts[1])
	]
}

# run_commands returns all RUN command strings
run_commands(content) := out if {
	out := [cmd | some inst in dockerfile_instructions(content, "run"); cmd := inst.value]
}

# expose_ports returns all EXPOSE port numbers
expose_ports(content) := out if {
	out := [port |
		some inst in dockerfile_instructions(content, "expose")
		parts := regex.split(`\s+`, inst.value)
		port_str := parts[0]
		port := to_number(port_str)
	]
}

# user_instructions returns all USER values
user_instructions(content) := out if {
	out := [user | some inst in dockerfile_instructions(content, "user"); user := inst.value]
}

# has_user checks if Dockerfile has USER instruction
has_user(content) if {
	some inst in dockerfile_instructions(content, "user")
}

# last_user_is_root checks if the last USER instruction is root
last_user_is_root(content) if {
	users := dockerfile_instructions(content, "user")
	count(users) > 0
	last_user := users[count(users) - 1]
	lower(last_user.value) == "root"
}

# count_instructions returns count of specific instruction type
count_instructions(content, instruction_type) := count(dockerfile_instructions(content, instruction_type))

# getPackages extracts package names from package manager command
get_packages(commands, command) := output if {
	index := indexof(commands, command[0])
	len := count(command[0])
	command_with_all := substring(commands, len + index, count(commands))
	contains(command_with_all, ";")
	command_with_all_no_tabs := replace(command_with_all, "\t", "")
	command_with_all_split := split(command_with_all_no_tabs, ";")
	packages := split(trim_space(command_with_all_split[0]), " ")
	output = packages
} else = output if {
	index := indexof(commands, command[0])
	len := count(command[0])
	command_with_all := substring(commands, len + index, count(commands))
	contains(command_with_all, "&&")
	command_with_all_split := split(command_with_all, "&&")
	packages := split(trim_space(command_with_all_split[0]), " ")
	output = packages
} else = output if {
	index := indexof(commands, command[0])
	len := count(command[0])
	command_with_all := substring(commands, len + index, count(commands))
	not contains(command_with_all, ";")
	not contains(command_with_all, "&&")
	packages := split(trim_space(command_with_all), " ")
	output = packages
}

# with_version checks if a package string contains version specification
with_version(pack) if {
	regex.match("[A-Za-z0-9_\\+-]+[-:][$](.+)", pack)
}

with_version(pack) if {
	regex.match("[A-Za-z0-9_\\+-]+[:-]([0-9]+.)+[0-9]+", pack)
}

with_version(pack) if {
	regex.match("[A-Za-z0-9_\\+-]+~?=(.+)", pack)
}

# array_contains checks if array contains any of the items in list
array_contains(array, list) if {
	contains(array[_], list[_])
}

# has_flag checks if a flag exists in the instruction value
has_flag(instruction, flag) if {
	contains(lower(instruction.value), lower(flag))
}

# is_last_from_scratch checks if the last FROM is scratch
is_last_from_scratch(content) if {
	images := from_images(content)
	count(images) > 0
	lower(images[count(images) - 1]) == "scratch"
}

# get_instruction_lines returns line numbers where instruction occurs
get_instruction_lines(content, instruction_type) := lines if {
	insts := dockerfile_instructions(content, instruction_type)
	lines := [inst.line | some inst in insts]
}

# run_command_contains checks if any RUN command contains pattern
run_command_contains(content, pattern) if {
	some cmd in run_commands(content)
	regex.match(pattern, cmd)
}

# is_json_array checks if value is a JSON array format
is_json_array(value) if {
	regex.match(`^\s*\[.*\]\s*$`, value)
}

# is_absolute_path checks if path is absolute
is_absolute_path(path) if {
	startswith(path, "/")
}

is_absolute_path(path) if {
	regex.match(`^[a-zA-Z]:[/\\]`, path)
}

is_absolute_path(path) if {
	startswith(path, "$")
}

# has_no_cache_flag checks if apk add has --no-cache
has_no_cache_flag(cmd) if {
	contains(cmd, "--no-cache")
}
