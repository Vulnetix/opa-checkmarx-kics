# Ported from checkmarx-kics: ecs_cluster_container_insights_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_ecs_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-ECS-01",
	"name": "ECS Cluster should have Container Insights enabled",
	"description": "AWS ECS Clusters should have Container Insights enabled for better monitoring and observability of container workloads.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ecs", "container", "insights", "monitoring"],
}

findings contains finding if {
	some r in tf.resources("aws_ecs_cluster")
	not tf.has_sub_block(r.block, "setting")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ecs_cluster %q is missing container insights setting.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

findings contains finding if {
	some r in tf.resources("aws_ecs_cluster")
	settings := tf.sub_blocks(r.block, "setting")
	count(settings) > 0
	not regex.match(`(?s)name(?i)\s*=\s*"containerInsights"`, settings[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ecs_cluster %q does not have containerInsights setting configured.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}

findings contains finding if {
	some r in tf.resources("aws_ecs_cluster")
	settings := tf.sub_blocks(r.block, "setting")
	count(settings) > 0
	setting_block := settings[0]
	regex.match(`(?s)name(?i)\s*=\s*"containerInsights"`, setting_block)
	not regex.match(`(?s)value(?i)\s*=\s*"enabled"`, setting_block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ecs_cluster %q has containerInsights setting not set to 'enabled'.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}
