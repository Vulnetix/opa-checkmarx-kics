# Ported from checkmarx-kics: ebs_volume_encryption_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_ebs_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-EBS-01",
	"name": "AWS EBS Volume should have encryption enabled",
	"description": "AWS EBS Volumes should have encryption enabled to protect data at rest. Volumes without encrypted=true or with encrypted=false are flagged.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ebs", "encryption", "security"],
}

# Report volumes without encrypted attribute defined
findings contains finding if {
	some r in tf.resources("aws_ebs_volume")
	not tf.has_key(r.block, "encrypted")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ebs_volume %q is missing encrypted attribute (should be true).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

# Report volumes with encrypted = false
findings contains finding if {
	some r in tf.resources("aws_ebs_volume")
	tf.bool_attr(r.block, "encrypted") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ebs_volume %q has encrypted = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
