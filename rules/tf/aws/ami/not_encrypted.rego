# Ported from checkmarx-kics: ami_not_encrypted.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_ec2_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-EC2-01",
	"name": "AWS AMI EBS Block Device should be encrypted",
	"description": "AWS AMI EBS Block Device should have encryption enabled. When creating AMIs from existing instances or snapshots, encryption must be enabled.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ami", "ec2", "encryption", "security"],
}

# ebs_block_device without encrypted attribute
findings contains finding if {
	some r in tf.resources("aws_ami")
	tf.has_sub_block(r.block, "ebs_block_device")
	not regex.match(`(?s)ebs_block_device(?i)\s*\{[^\}]*encrypted(?i)\s*=\s*true`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ami %q has ebs_block_device without encrypted = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

# ebs_block_device with encrypted = false
findings contains finding if {
	some r in tf.resources("aws_ami")
	tf.has_sub_block(r.block, "ebs_block_device")
	regex.match(`(?s)ebs_block_device(?i)\s*\{[^\}]*encrypted(?i)\s*=\s*false`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ami %q has ebs_block_device with encrypted = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

# missing ebs_block_device entirely
findings contains finding if {
	some r in tf.resources("aws_ami")
	not tf.has_sub_block(r.block, "ebs_block_device")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ami %q is missing ebs_block_device configuration.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 2),
	}
}
