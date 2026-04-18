# opa-checkmarx-kics

Vulnetix-compatible OPA/Rego IaC security rules, adapted from the intent of [Checkmarx KICS](https://github.com/Checkmarx/kics) ("Keeping Infrastructure as Code Secure").

## Clean-room approach

These rules were produced using a **clean-room** methodology:

1. The **intent** of each upstream KICS rule was studied — what misconfiguration it detects, why it matters, and what remediation it recommends.
2. Detection logic was then **written from scratch** against the Vulnetix `input.file_contents` schema.
3. **No upstream KICS Rego code was copied.** The original KICS rules operate on a fundamentally different input schema (parsed document-model structures produced by KICS' Go loader), so they cannot be used verbatim with Vulnetix.
4. The helper libraries (`rules/_lib/dockerfile.rego`, `rules/_lib/terraform.rego`, `rules/_lib/ansible.rego`) are original implementations that parse raw file text using regex — they are not derived from KICS' Go-side parsers.

The result is a set of rules that match the **security intent** of the upstream KICS checks while being natively compatible with the Vulnetix CLI's `--rule` mechanism.

## Coverage

| Category | Rules | ID prefix | Description |
|----------|-------|-----------|-------------|
| Dockerfile | 48 | `KICS-DOCKER-*` | Best practices: ADD vs COPY, root user, package pinning, HEALTHCHECK, port exposure, etc. |
| Ansible AWS | 14 | `KICS-ANSIBLE-AWS-*` | Cloud security: S3 versioning/ACL, CloudTrail, RDS backups, EBS encryption, open ports |
| Terraform AWS | 16 | `KICS-TF-AWS-*` | S3, EBS, RDS, ECS, EKS, Lambda, VPC, AMI security checks |
| Terraform Azure | 53 | `KICS-TF-AZURE-*` | AKS, App Service, SQL/PostgreSQL/Redis, Key Vault, Storage, Network security |
| Terraform GCP | 74 | `KICS-TF-GCP-*` | GKE, Compute, Storage, IAM, KMS, SQL, DNS, Network security checks |

## Layout

```
opa-checkmarx-kics/
├── LICENSE                          ← Apache 2.0
├── README.md
└── rules/
    ├── _lib/
    │   ├── dockerfile.rego          # package vulnetix.kics.dockerfile
    │   ├── terraform.rego           # package vulnetix.kics.tf
    │   └── ansible.rego             # package vulnetix.kics.ansible
    ├── docker/<rule>.rego           # package vulnetix.rules.kics_docker_*
    ├── ansible/aws/<rule>.rego      # package vulnetix.rules.kics_ansible_*
    └── tf/
        ├── aws/<service>/*.rego     # package vulnetix.rules.kics_tf_aws_*
        ├── azure/<service>/*.rego   # package vulnetix.rules.kics_tf_azure_*
        └── gcp/<service>/*.rego     # package vulnetix.rules.kics_tf_gcp_*
```

## Usage

```bash
# Use alongside built-in rules
vulnetix scan --rule Vulnetix/opa-checkmarx-kics

# Use only these rules (disable built-ins)
vulnetix scan --rule Vulnetix/opa-checkmarx-kics --disable-default-rules

# Combine with other custom rule repos
vulnetix scan \
  --rule Vulnetix/opa-checkmarx-kics \
  --rule Vulnetix/opa-aquasecurity-trivy
```

## Input schema

Rules operate on Vulnetix's `input.file_contents` map (file path → raw file text):

```json
{
  "file_contents": {
    "Dockerfile": "FROM ubuntu:22.04\n...",
    "main.tf": "resource \"aws_s3_bucket\" ...\n...",
    "playbook.yml": "- name: Create S3 bucket\n..."
  }
}
```

- Dockerfile rules parse instructions via the `dockerfile` helper library (regex-based line parsing)
- Terraform rules parse HCL blocks via the `tf` helper library (regex-based block extraction)
- Ansible rules parse YAML tasks via the `ansible` helper library (regex-based task matching)
- No cluster access, no cloud APIs, no registry fetches — purely local file scanning

## Attribution

The security checks in this repository are inspired by [Checkmarx KICS](https://github.com/Checkmarx/kics), which is licensed under the [Apache License 2.0](https://github.com/Checkmarx/kics/blob/master/LICENSE).

Copyright (c) Checkmarx Ltd. The upstream KICS project is the original source of the misconfiguration categories and security rationale that these rules are based on.

This repository is licensed under [Apache 2.0](LICENSE).
