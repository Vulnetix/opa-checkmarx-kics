# Ported from checkmarx-kics: eks_cluster_has_public_access_cidrs.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_eks_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-EKS-01",
	"name": "EKS Cluster should not allow unrestricted public access",
	"description": "AWS EKS Clusters with public endpoint access should not allow unrestricted CIDR access (0.0.0.0/0). The default is 0.0.0.0/0 if not specified.",
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
	"tags": ["terraform", "aws", "eks", "kubernetes", "public", "security"],
}

# Public access enabled with 0.0.0.0/0 in public_access_cidrs
findings contains finding if {
	some r in tf.resources("aws_eks_cluster")
	tf.has_sub_block(r.block, "vpc_config")
	vpc := tf.sub_blocks(r.block, "vpc_config")
	count(vpc) > 0
	tf.bool_attr(vpc[0], "endpoint_public_access") == true
	# Check for 0.0.0.0/0 in public_access_cidrs
	regex.match(`(?s)public_access_cidrs(?i)\s*=\s*\[[^\]]*"0\.0\.0\.0/0"`, vpc[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_eks_cluster %q has vpc_config.endpoint_public_access=true with public_access_cidrs containing 0.0.0.0/0.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 10),
	}
}

# Missing public_access_cidrs when public_access is enabled (defaults to 0.0.0.0/0)
findings contains finding if {
	some r in tf.resources("aws_eks_cluster")
	tf.has_sub_block(r.block, "vpc_config")
	vpc := tf.sub_blocks(r.block, "vpc_config")
	count(vpc) > 0
	tf.bool_attr(vpc[0], "endpoint_public_access") == true
	not tf.has_key(vpc[0], "public_access_cidrs")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_eks_cluster %q has vpc_config.endpoint_public_access=true without public_access_cidrs (defaults to 0.0.0.0/0).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 10),
	}
}
