# Ported from checkmarx-kics: lambda_permission_principal_is_wildcard.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_lambda_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-LAMBDA-01",
	"name": "Lambda Permission should not use wildcard principal",
	"description": "AWS Lambda Permissions should not use a wildcard (*) principal. Using wildcards in the principal allows any entity to invoke the function.",
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
	"tags": ["terraform", "aws", "lambda", "permission", "wildcard", "security"],
}

findings contains finding if {
	some r in tf.resources("aws_lambda_permission")
	principal := tf.string_attr(r.block, "principal")
	contains(principal, "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_lambda_permission %q has a wildcard (*) principal.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
