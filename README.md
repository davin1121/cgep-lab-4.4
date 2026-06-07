# GRC Evidence Pipeline: AWS + GitHub Actions

## What This Is

A fully automated compliance gate that runs on every pull request targeting `main`. When a developer opens a PR with Terraform infrastructure changes, GitHub Actions automatically authenticates to AWS using OIDC (no stored credentials), generates a Terraform plan, evaluates it against three NIST 800-53 Rego policies, runs a static security scan with tfsec, and uploads a timestamped evidence artifact. All of this runs before a single resource touches AWS. Non-compliant PRs are blocked at the gate. Compliant PRs produce a signed, immutable evidence bundle attached to the commit that triggered them.

## What It Enforces and Why It Matters

The pipeline enforces three NIST 800-53 controls on every infrastructure change:

| Control | Policy | What it checks |
|---|---|---|
| SC-28 | `sc28_encryption_aws.rego` | Every S3 bucket has a matching `aws_s3_bucket_server_side_encryption_configuration` |
| AC-3 | `ac3_no_public_aws.rego` | All four public access block flags are set to true on every S3 bucket |
| CM-6 | `cm6_required_tags_aws.rego` | All resources carry the required compliance tags |

Most compliance programs find violations after deployment, during a quarterly scan, an audit, or an incident. This pipeline finds them before deployment, at the point where the cost of fixing them is a one-line code change rather than an emergency remediation event. The developer sees the violation name, the resource, and the remediation in the PR. Not in a findings report six weeks later.

The evidence artifact produced on every run answers the auditor's question directly: *"How do you know every infrastructure change was compliance-checked before it reached production?"* The answer is a URL to a workflow run with a timestamped artifact containing `plan.json`, `conftest-results.json`, and `tfsec.sarif`.

## Key Design Decisions

**OIDC instead of stored credentials.** The workflow authenticates to AWS by having GitHub mint a short-lived identity token that AWS verifies against the OIDC provider created in `oidc/main.tf`. No AWS access keys are stored anywhere. The IAM role is scoped to this specific repository so no other GitHub repo can assume it. This eliminates the most common CI/CD credential leak vector.

**`if: always()` on evidence upload.** The tfsec scan and artifact upload steps run even when Conftest fails. Without this, a policy failure would abort the job before evidence was captured. The failure evidence is as important as the pass evidence. Both go in the audit record.

**`|| true` with a separate Python check.** Conftest and tfsec exit non-zero when they find violations. Using `|| true` lets the script collect all results before making the pass/fail decision. The inline Python script then counts failures and sets the final exit code. This ensures all namespaces are evaluated even if the first one fails.

**Three AWS-specific namespaces only.** The generic Lab 3.3 policies (`compliance.cm6`) check for different tag key names than the AWS Terraform module uses. Running both causes false positives. The AWS variants cover the same controls with field names that match the actual plan JSON structure.

## Results

**Green PR** (`add-grc-gate`): All three namespaces passed. Workflow completed in 28 seconds. Evidence artifact captured.

**Red PR** (`break-encryption`): SC-28 gate fired. `aws_s3_bucket.primary` had no matching encryption configuration. AC-3 and CM-6 both passed. The gate is surgical, not a blanket failure. Merge blocked. Evidence artifact captured with the exact violation message and remediation step.

```json
{
  "namespace": "compliance.sc28_aws",
  "successes": 0,
  "failures": [
    {
      "msg": "[SC-28] aws_s3_bucket.primary: aws_s3_bucket has no matching aws_s3_bucket_server_side_encryption_configuration. Remediation: add one referencing this bucket."
    }
  ]
}
```

## How to Reproduce

**Prerequisites:** AWS account, GitHub repo, AWS CLI configured locally.

**1. Create the OIDC trust in AWS:**
```bash
cd oidc
terraform init
terraform apply -var="github_org=YOUR_ORG" -var="github_repo=YOUR_REPO"
```

**2. Add the role ARN as a GitHub repo variable:**

GitHub repo → Settings → Secrets and variables → Actions → Variables → New repository variable
- Name: `AWS_ROLE_ARN`
- Value: output from step 1

**3. Push the workflow to a branch and open a PR targeting `main`.** The pipeline fires automatically.

**4. To demonstrate the gate blocking a violation:** Remove `aws_s3_bucket_server_side_encryption_configuration` from `terraform/main.tf`, open a PR, and watch Conftest fire SC-28.

**Cleanup:** Delete test branches. The IAM role and OIDC provider are free so leave them in place. Lab 4.4 builds on this by adding Cosign signing and uploading the evidence bundle to the Lab 2.5 vault.
