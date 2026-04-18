# Ported from checkmarx-kics: ebs_default_encryption_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_ebs_02

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-EBS-02",
	"name": "AWS EBS Default Encryption should be enabled",
	"description": "AWS EBS Default Encryption should be enabled to ensure all new EBS volumes are automatically encrypted.",
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

findings contains finding if {
	some r in tf.resources("aws_ebs_encryption_by_default")
	tf.bool_attr(r.block, "enabled") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ebs_encryption_by_default %q has enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
