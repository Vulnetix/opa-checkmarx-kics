# Adapted from https://github.com/Checkmarx/kics (S3 Bucket Logging Disabled).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Checks if S3 buckets have access logging enabled.

package vulnetix.rules.kics_tf_aws_s3_02

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-S3-02",
	"name": "S3 bucket logging disabled",
	"description": "S3 bucket access logging should be enabled for security auditing and compliance requirements.",
	"help_uri": "https://docs.kics.io/latest/queries/terraform-queries/aws/s3-bucket-logging-disabled",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "logging", "audit"],
}

# Find buckets without logging enabled (inline logging block)
findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not tf.has_sub_block(b.block, "logging")
	not _has_separate_logging_resource(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q does not have logging enabled.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(b.block, 3),
	}
}

# Find buckets with logging block but no target_bucket
findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	tf.has_sub_block(b.block, "logging")
	some l in tf.sub_blocks(b.block, "logging")
	not tf.has_key(l, "target_bucket")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has logging block but target_bucket is not defined.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(b.block, 5),
	}
}

# Find aws_s3_bucket_logging resources without target_bucket
findings contains finding if {
	some l in tf.resources("aws_s3_bucket_logging")
	not tf.has_key(l.block, "target_bucket")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_logging %q does not have target_bucket defined.", [l.name]),
		"artifact_uri": l.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(l.block, 5),
	}
}

# Helper: Check if there's a separate aws_s3_bucket_logging resource for this bucket
_has_separate_logging_resource(bucket_name) if {
	some l in tf.resources("aws_s3_bucket_logging")
	tf.references(l.block, "aws_s3_bucket", bucket_name)
}
