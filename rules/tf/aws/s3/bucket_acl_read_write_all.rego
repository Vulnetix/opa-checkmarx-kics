# Ported from checkmarx-kics: s3_bucket_acl_allows_read_or_write_to_all_users.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_s3_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-S3-01",
	"name": "S3 Bucket ACL should not allow public read or write access",
	"description": "S3 Bucket ACL should be set to private. Values like 'public-read' or 'public-read-write' expose bucket contents to the public.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "public", "acl", "security"],
}

findings contains finding if {
	some r in tf.resources("aws_s3_bucket")
	acl := tf.string_attr(r.block, "acl")
	acl == "public-read"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has ACL set to 'public-read'.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("aws_s3_bucket")
	acl := tf.string_attr(r.block, "acl")
	acl == "public-read-write"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has ACL set to 'public-read-write'.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("aws_s3_bucket_acl")
	acl := tf.string_attr(r.block, "acl")
	acl == "public-read"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl %q has ACL set to 'public-read'.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("aws_s3_bucket_acl")
	acl := tf.string_attr(r.block, "acl")
	acl == "public-read-write"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl %q has ACL set to 'public-read-write'.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
