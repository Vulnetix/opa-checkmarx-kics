# Ported from checkmarx-kics: default_security_groups_with_unrestricted_traffic.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_vpc_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-VPC-01",
	"name": "Default AWS Security Group should not allow unrestricted traffic",
	"description": "AWS Default Security Groups should not allow unrestricted ingress or egress traffic (0.0.0.0/0 or ::/0). Default security groups should be unused.",
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
	"tags": ["terraform", "aws", "vpc", "security_group", "default", "security"],
}

findings contains finding if {
	some r in tf.resources("aws_default_security_group")
	tf.has_open_cidr(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_default_security_group %q has unrestricted CIDR blocks (0.0.0.0/0 or ::/0).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}
