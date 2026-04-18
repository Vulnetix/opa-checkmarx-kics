# Helper library for checkmarx-kics Ansible rules.
# Provides regex-based extraction for Ansible YAML files.
# Mirrors the pattern used in rules/fugue-regula/_lib/tf.rego.

package vulnetix.kics.ansible

import rego.v1

is_ansible_yaml(path) if {
	lower(path) != ""
	endswith(lower(path), ".yml")
}

is_ansible_yaml(path) if {
	lower(path) != ""
	endswith(lower(path), ".yaml")
}

# Match common Ansible AWS module patterns (amazon.aws.* and short names)
is_aws_module(module_name) if startswith(lower(module_name), "amazon.aws.")
is_aws_module(module_name) if {
	short_names := {
		"s3_bucket", "aws_s3", "ec2", "ec2_group", "ec2_instance", "rds", "rds_instance",
		"lambda", "iam", "kms", "sns", "sqs", "cloudwatch", "cloudtrail", "efs",
		"elb", "elbv2", "autoscaling", "ecs", "ecr", "redshift", "elasticache",
	}
	short_names[module_name]
}

# Find all Ansible task blocks in YAML content.
# Each task typically looks like:
#   - name: Task Name
#     module_name:
#       option1: value1
#       option2: value2
task_blocks(content) := out if {
	# Match list items that start tasks (-- preceded by newline or start of string)
	# This pattern matches YAML list items with a name field
	pattern := `(?s)-\s+name:[^\n]*\n(?:[^-].*|\s+.*)*?(?=\n-\s+name:|\n---|$)`
	blocks := regex.find_n(pattern, content, -1)
	out := [trim_space(b) | some b in blocks; count(trim_space(b)) > 0]
}

# Find tasks in a file that use a specific module
tasks_with_module(content, module_name) := out if {
	module_pattern := sprintf(`(?m)^\s+%s(?:\.\w+)*:\s*(?:$|\n)`, [module_name])
	all_tasks := task_blocks(content)
	out := [task |
		some task in all_tasks
		regex.match(module_pattern, task)
	]
}

# Extract the task name from a task block
task_name(block) := name if {
	matches := regex.find_n(`(?m)^\s*-\s+name:\s*(.+)$`, block, 1)
	count(matches) > 0
	name := trim_space(matches[0])
} else = "unnamed task"

# Get the start line of a task block in content
task_start_line(content, block) := line_num if {
	# Count newlines before the block appears
	idx := indexof(content, block)
	idx >= 0
	before_block := substring(content, 0, idx)
	lines := regex.find_n(`\n`, before_block, -1)
	line_num := count(lines) + 1
} else = 1

# Check if task is NOT in "absent" state (typical security check)
is_present_state(block) if {
	not regex.match(`(?m)state:\s*absent`, block)
}

# Check if a value represents ansible "true" (yes, true, True, etc.)
is_true(val) if lower(val) == "yes"
is_true(val) if lower(val) == "true"
is_true(val) if val == true

# Check if a value represents ansible "false" (no, false, False, etc.)
is_false(val) if lower(val) == "no"
is_false(val) if lower(val) == "false"
is_false(val) if val == false

# Extract string value for a key from a block
string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s:\s*["']?([^"'\n]+?)["']?(?:\s*$|\s*#)`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	val := trim_space(matches[0])
} else = ""

# Check if a block has a specific key
has_key(block, key) if {
	pattern := sprintf(`(?m)^\s*%s:`, [key])
	regex.match(pattern, block)
}

# Find all occurrences of a pattern that indicates a security issue
# Returns list of objects with match text and line number
find_pattern_occurrences(content, pattern) := out if {
	matches := regex.find_n(pattern, content, -1)
	out := [{"match": m, "line": _line_of_match(content, m)} | some m in matches]
}

_line_of_match(content, match) := line_num if {
	idx := indexof(content, match)
	idx >= 0
	prefix := substring(content, 0, idx)
	lines := regex.find_all_string_submatch_n(`\n`, prefix, -1)
	line_num := count(lines) + 1
} else = 1

# True if a task body declares a `pending_window_in_days` field.
has_pending_window(task) if regex.match(`(?m)^\s*pending_window_in_days\s*:`, task)

# True if a task body declares `enable_key_rotation` (regardless of value).
has_rotation(task) if regex.match(`(?m)^\s*enable_key_rotation\s*:`, task)

# True if a task is either marked for pending deletion or has rotation configured.
has_pending_window_or_rotation(task) if has_pending_window(task)

has_pending_window_or_rotation(task) if has_rotation(task)

# Get snippet around a specific line in content (window = 3 lines either side).
snippet_around_line(content, line_num) := snippet_around_line_n(content, line_num, 3)

snippet_around_line_n(content, line_num, window) := snippet if {
	lines := split(content, "\n")
	start := _max2(0, line_num - window - 1)
	end := _min2(count(lines), line_num + window)
	snippet_lines := array.slice(lines, start, end)
	snippet := concat("\n", snippet_lines)
}

_max2(a, b) := a if a >= b

_max2(a, b) := b if a < b

_min2(a, b) := a if a <= b

_min2(a, b) := b if a > b

# Extract block of text representing a specific module's configuration within a task
module_config_block(task_block, module_name) := config if {
	# Find module config from module_name: to next module or end of task
	pattern := sprintf(`(?s)^\s+%s(?:\.\w+)*:\s*(?:\n|$)((?:\s+.+\n?)*)`, [module_name])
	matches := regex.find_all_string_submatch_n(pattern, task_block, 1)
	count(matches) > 0
	config := trim_space(matches[0][1])
} else = ""

# Check if content contains unrestricted CIDR blocks (0.0.0.0/0 or ::/0)
has_unrestricted_cidr(block) if {
	regex.match(`["']?0\.0\.0\.0/0["']?`, block)
}

has_unrestricted_cidr(block) if {
	regex.match(`["']?::/0["']?`, block)
}

# Check for port numbers in a rule block
has_port(block, port) if {
	# Matches patterns like from_port: 80, to_port: 80, ports: 80, ports: "80"
	pattern := sprintf(`(?m)(?:from_port|to_port|ports?):\s*["']?%d["']?\b`, [port])
	regex.match(pattern, block)
}

# Parse S3 bucket policy JSON text from a block (for checks on policy content)
policy_text(block) := policy if {
	# Match policy: followed by JSON (either inline or in quote blocks)
	pattern := `(?s)policy:\s*('\s*\{.*?\}\s*'|"\s*\{.*?\}\s*"|\{[^}]*(?:\{[^}]*\}[^}]*)*\})`
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	policy := trim_space(matches[0])
} else = ""

# Get the line number where a specific pattern appears
find_pattern_line(content, pattern) := line_num if {
	matches := regex.find_all_string_submatch_n(pattern, content, 1)
	count(matches) > 0
	match_text := matches[0][0]
	idx := indexof(content, match_text)
	idx >= 0
	prefix := substring(content, 0, idx)
	line_count := regex.find_all_string_submatch_n(`\n`, prefix, -1)
	line_num := count(line_count) + 1
} else = 1
