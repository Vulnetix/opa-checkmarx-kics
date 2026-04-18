# Adapted from https://github.com/Checkmarx/kics (S3 Bucket ACL Allows Read or Write to All Users).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Checks if S3 bucket ACL allows public access.

package vulnetix.rules.kics_tf_aws_s3_03

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-S3-03",
	"name": "S3 bucket ACL allows public access",
	"description": "S3 bucket ACL should not allow public-read, public-read-write, or authenticated-read access. These permissions expose bucket contents.",
	"help_uri": "https://docs.kics.io/latest/queries/terraform-queries/aws/s3-bucket-acl-allows-read-or-write-to-all-users",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-732"],
	"capec": [],
	"attack_technique": ["T1222"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "acl", "public-access"],
}

# List of dangerous ACL values
_dangerous_acls := {"public-read", "public-read-write", "authenticated-read"}

# Find buckets with dangerous inline ACL
findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	acl := tf.string_attr(b.block, "acl")
	acl in _dangerous_acls
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has dangerous ACL value '%s'.", [b.name, acl]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(b.block, 5),
	}
}

# Find aws_s3_bucket_acl resources with dangerous ACL values
findings contains finding if {
	some a in tf.resources("aws_s3_bucket_acl")
	acl := tf.string_attr(a.block, "acl")
	acl in _dangerous_acls
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl %q has dangerous ACL value '%s'.", [a.name, acl]),
		"artifact_uri": a.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(a.block, 5),
	}
}

# Find aws_s3_bucket_acl with access_control_policy sub-block granting public access
findings contains finding if {
	some a in tf.resources("aws_s3_bucket_acl")
	tf.has_sub_block(a.block, "access_control_policy")
	some p in tf.sub_blocks(a.block, "access_control_policy")
	tf.has_sub_block(p, "grant")
	some g in tf.sub_blocks(p, "grant")
	grantee := tf.sub_blocks(g, "grantee")
	count(grantee) > 0
	some gr in grantee
	type_val := tf.string_attr(gr, "type")
	type_val == "Group"
	uri := tf.string_attr(gr, "uri")
	contains(uri, "AllUsers")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl %q grants access to AllUsers via access_control_policy.", [a.name]),
		"artifact_uri": a.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(a.block, 10),
	}
}
