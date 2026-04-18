# Ported from checkmarx-kics: ecs_services_assigned_with_public_ip_address.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_ecs_02

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-ECS-02",
	"name": "ECS Service should not assign public IP",
	"description": "AWS ECS Services should not have network_configuration.assign_public_ip set to true. This exposes the service to the public internet.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ecs", "service", "public", "network"],
}

findings contains finding if {
	some r in tf.resources("aws_ecs_service")
	tf.has_sub_block(r.block, "network_configuration")
	net := tf.sub_blocks(r.block, "network_configuration")
	count(net) > 0
	tf.bool_attr(net[0], "assign_public_ip") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ecs_service %q has network_configuration.assign_public_ip = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}
