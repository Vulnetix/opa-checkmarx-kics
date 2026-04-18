# Adapted from https://github.com/Checkmarx/kics (S3 Bucket Without Versioning).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Checks if S3 buckets have versioning enabled.

package vulnetix.rules.kics_tf_aws_s3_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-S3-01",
	"name": "S3 bucket without versioning",
	"description": "S3 bucket versioning should be enabled to protect against accidental deletion and provide recovery capabilities.",
	"help_uri": "https://docs.kics.io/latest/queries/terraform-queries/aws/s3-bucket-without-versioning",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "versioning", "backup"],
}

# Find buckets without versioning enabled
findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not _has_versioning_block(b.block)
	not _has_separate_versioning_resource(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q does not have versioning enabled.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

# Find buckets with versioning enabled but set to false
findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	tf.has_sub_block(b.block, "versioning")
	some v in tf.sub_blocks(b.block, "versioning")
	tf.is_not_true(v, "enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has versioning block but enabled is not set to true.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(b.block, 5),
	}
}

# Find aws_s3_bucket_versioning resources with suspended status
findings contains finding if {
	some v in tf.resources("aws_s3_bucket_versioning")
	tf.string_attr(v.block, "versioning_configuration.status") == "Suspended"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_versioning %q has versioning_configuration.status set to 'Suspended'.", [v.name]),
		"artifact_uri": v.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(v.block, 5),
	}
}

# Find aws_s3_bucket_versioning resources with Disabled status
findings contains finding if {
	some v in tf.resources("aws_s3_bucket_versioning")
	tf.string_attr(v.block, "versioning_configuration.status") == "Disabled"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_versioning %q has versioning_configuration.status set to 'Disabled'.", [v.name]),
		"artifact_uri": v.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(v.block, 5),
	}
}

# Helper: Check if bucket has versioning sub-block
_has_versioning_block(block) if tf.has_sub_block(block, "versioning")

# Helper: Check if there's a separate aws_s3_bucket_versioning resource for this bucket
_has_separate_versioning_resource(bucket_name) if {
	some v in tf.resources("aws_s3_bucket_versioning")
	tf.references(v.block, "aws_s3_bucket", bucket_name)
}
