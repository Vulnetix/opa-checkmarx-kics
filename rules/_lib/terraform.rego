# Helper package — not a rule.
# Regex-based HCL extraction for checkmarx-kics Terraform ports.
# Mirrors the pattern used in rules/fugue-regula/_lib/tf.rego.

package vulnetix.kics.tf

import rego.v1

# Returns true if the file path ends with .tf (case insensitive)
is_tf(path) if endswith(lower(path), ".tf")

# Extract resource blocks of a specific type from Terraform content
# Uses regex to match nested braces properly (up to 2 levels deep)
resource_blocks(content, type) := out if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
	out := [r |
		some b in blocks
		name := _block_name(b)
		r := {"block": b, "name": name, "type": type}
	]
}

# Get all resources of a specific type across all files in input.file_contents
resources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some rb in resource_blocks(content, type)
		r := {"path": path, "block": rb.block, "name": rb.name, "type": rb.type}
	]
}

# Extract data blocks of a specific type from Terraform content
data_blocks(content, type) := out if {
	pattern := sprintf(`(?s)data\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
	out := [r |
		some b in blocks
		name := _block_name(b)
		r := {"block": b, "name": name, "type": type}
	]
}

# Get all data sources of a specific type across all files in input.file_contents
data_sources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some rb in data_blocks(content, type)
		r := {"path": path, "block": rb.block, "name": rb.name, "type": rb.type}
	]
}

# Extract the block name from a resource/data block string
# Looks for the second quoted string (first is the resource type)
_block_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 2)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

# Extract a string attribute value (e.g., key = "value") from a block
string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	caps := regex.find_n(`"([^"]*)"`, matches[0], 1)
	count(caps) > 0
	val := trim(caps[0], `"`)
}

# Extract all string attribute values matching a key pattern
string_attrs(block, key) := vals if {
	pattern := sprintf(`(?m)%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, -1)
	vals := [v |
		some m in matches
		caps := regex.find_n(`"([^"]*)"`, m, 1)
		count(caps) > 0
		v := trim(caps[0], `"`)
	]
}

# Extract a boolean attribute value from a block (true/false)
bool_attr(block, key) := b if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*(true|false)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	b := regex.match(`=\s*true\b`, matches[0])
}

# Extract a numeric attribute value from a block
number_attr(block, key) := n if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*([0-9]+)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	digits := regex.find_n(`[0-9]+`, matches[0], -1)
	count(digits) > 0
	n := to_number(digits[count(digits) - 1])
}

# Extract a list of strings from an attribute (e.g., key = ["a", "b"])
string_list_attr(block, key) := vals if {
	pattern := sprintf(`(?s)%s\s*=\s*\[([^\]]*)\]`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	body := matches[0]
	items := regex.find_n(`"([^"]*)"`, body, -1)
	vals := [v | some i in items; v := trim(i, `"`)]
}

# Check if a block has a specific attribute key defined
has_key(block, key) if {
	pattern := sprintf(`(?m)^\s*%s\s*=`, [key])
	regex.match(pattern, block)
}

# Check if a block has a specific sub-block defined
has_sub_block(block, name) if {
	regex.match(sprintf(`(?s)\b%s\s*\{`, [name]), block)
}

# Extract sub-blocks by name (returns array of block content strings)
sub_blocks(block, name) := subs if {
	pattern := sprintf(`(?s)\b%s\s*\{((?:[^{}]|\{[^{}]*\})*?)\}`, [name])
	subs := regex.find_n(pattern, block, -1)
}

# Check if an attribute is not set to true (missing, false, or "false")
is_not_true(block, key) if not has_key(block, key)
is_not_true(block, key) if bool_attr(block, key) == false
is_not_true(block, key) if string_attr(block, key) == "false"

# Check if an attribute is not set to false (missing, true, or "true")
is_not_false(block, key) if not has_key(block, key)
is_not_false(block, key) if bool_attr(block, key) == true
is_not_false(block, key) if string_attr(block, key) == "true"

# Strict: attribute exists and is boolean/string "true".
is_true(block, key) if bool_attr(block, key) == true

is_true(block, key) if string_attr(block, key) == "true"

# Strict: attribute exists and is boolean/string "false".
is_false(block, key) if bool_attr(block, key) == false

is_false(block, key) if string_attr(block, key) == "false"

# True if `key` is missing or set to true.
not_existing_or_true(block, key) if not has_key(block, key)

not_existing_or_true(block, key) if is_true(block, key)

# True if `key` is missing or set to false.
not_existing_or_false(block, key) if not has_key(block, key)

not_existing_or_false(block, key) if is_false(block, key)

# Cross-resource reference detection
# Checks if referrer_block contains a reference to type.name (e.g., aws_vpc.main)
references(referrer_block, ref_type, ref_name) if {
	regex.match(sprintf(`\b%s\.%s\b`, [ref_type, ref_name]), referrer_block)
}

# Extract heredoc content for a specific attribute
heredoc_attrs(block, key) := out if {
	pattern := sprintf(`(?s)%s\s*=\s*<<-?([A-Za-z0-9_]+)\s*\n(.*?)\n\s*\1\b`, [key])
	matches := regex.find_all_string_submatch_n(pattern, block, -1)
	out := [m[2] | some m in matches]
}

# Get the line number of a matched pattern in content
# Returns 1 if not found (safest default)
get_line_number(content, pattern) := line if {
	lines := split(content, "\n")
	some i, l in lines
	regex.match(pattern, l)
	line := i + 1
} else := 1

# 1-based line number where `block` first appears in `content`.
line_number_for_block(content, block) := line if {
	head := _block_head(block)
	head != ""
	idx := indexof(content, head)
	idx >= 0
	prefix := substring(content, 0, idx)
	line := count(split(prefix, "\n"))
} else := 1

# 1-based line number of the line inside `sub` that declares `key`.
# Falls back to the first line the `key =` assignment appears in the full content.
line_number(content, sub, key) := line if {
	pattern := sprintf(`(?m)^\s*%s\s*=`, [key])
	sub_start := indexof(content, _block_head(sub))
	sub_start >= 0
	prefix := substring(content, 0, sub_start)
	base := count(split(prefix, "\n"))
	sub_lines := split(sub, "\n")
	some i, l in sub_lines
	regex.match(pattern, l)
	line := base + i
} else := 1

_block_head(block) := head if {
	lines := split(block, "\n")
	count(lines) > 0
	head := lines[0]
} else := ""

# Extract `window` lines around a 1-based `line_num` from `content`.
extract_context(content, line_num, window) := snippet if {
	lines := split(content, "\n")
	total := count(lines)
	start := _max2(0, line_num - window - 1)
	end := _min2(total, line_num + window)
	snippet := concat("\n", array.slice(lines, start, end))
}

_max2(a, b) := a if a >= b

_max2(a, b) := b if a < b

_min2(a, b) := a if a <= b

_min2(a, b) := b if a > b

# Extract the first N lines of a block for snippet generation
block_snippet(block, max_lines) := snippet if {
	all_lines := split(block, "\n")
	count(all_lines) <= max_lines
	snippet := block
} else := snippet if {
	all_lines := split(block, "\n")
	count(all_lines) > max_lines
	lines := [all_lines[i] | some i in numbers.range(0, max_lines - 1)]
	snippet := concat("\n", lines)
}

# Check if content contains a pattern (case insensitive)
contains_pattern_ci(content, pattern) if {
	regex.match(pattern, lower(content))
}

# Valid key check - whether an attribute-like key exists in text
valid_key_text(block, key) if {
	regex.match(sprintf(`(?m)^\s*%s\s*[=\{]`, [key]), block)
}

# Check for CIDR blocks that are open to the world (0.0.0.0/0 or ::/0)
has_open_cidr(block) if {
	regex.match(`["']0\.0\.0\.0/0["']`, block)
} else if {
	regex.match(`["']::/0["']`, block)
}

# Known GCP public IAM member identifiers
public_users := {"allUsers", "allAuthenticatedUsers"}

# Check for sensitive ports in security group rules
has_sensitive_port(block, port) if {
	pattern := sprintf(`from_port\s*=\s*(%d|0)\b`, [port])
	regex.match(pattern, block)
	to_pattern := sprintf(`to_port\s*=\s*(%d|[0-9]+)\b`, [port])
	regex.match(to_pattern, block)
}
