# GRC Evidence Pipeline with Chain of Custody: AWS + GitHub Actions + Cosign

## What This Is

This lab extends the Lab 4.3 GRC pipeline with cryptographic evidence signing and immutable vault storage. On every pull request targeting `main`, the workflow authenticates to AWS using OIDC, runs a Terraform plan, evaluates it against three NIST 800-53 Rego policies, runs a static security scan with tfsec, then does something Lab 4.3 did not: it bundles all the evidence files, signs the bundle with Cosign using a keyless Sigstore identity, and uploads the signed bundle to an S3 Object Lock vault where it cannot be deleted or modified until the retention date expires.

Non-compliant PRs are blocked. Compliant PRs are merged. In both cases the evidence is signed, timestamped by Sigstore's Rekor transparency log, and locked in the vault. The chain of custody holds regardless of the outcome.

## Why Chain of Custody Matters

Without signing, evidence is just files. Anyone with the right AWS permissions could overwrite them. Anyone reviewing them has to take your word for it that they came from the pipeline.

With chain of custody, an auditor can run one script and get a mathematical proof that a specific evidence bundle was produced by a specific GitHub Actions workflow, has not been modified since it was created, was created at the time the CI run says it was, and cannot be deleted before the retention date. None of that requires trusting the person presenting the evidence.

This directly supports audit requirements in FedRAMP, SOC 2, and HIPAA that call for integrity and retention controls on audit records. Those frameworks do not say "upload files to S3." They say the records must be protected against unauthorized modification. Object Lock plus Cosign is how you prove that protection actually works.

## What It Enforces

The pipeline enforces three NIST 800-53 controls on every infrastructure change:

| Control | Policy | What it checks |
|---|---|---|
| SC-28 | `sc28_encryption_aws.rego` | Every S3 bucket has a matching encryption configuration |
| AC-3 | `ac3_no_public_aws.rego` | All four public access block flags are set to true |
| CM-6 | `cm6_required_tags_aws.rego` | All resources carry the required compliance tags |

## Key Design Decisions

**Keyless Cosign signing.** The workflow signs the evidence bundle using the same OIDC token used to authenticate to AWS. There are no signing keys to rotate, store, or leak. Sigstore's Fulcio CA issues a short-lived certificate containing the GitHub workflow identity, and that certificate is logged in Sigstore's Rekor transparency log. The Rekor log is public and append-only, outside this AWS account and outside GitHub. Verification does not require access to either.

**`if: always()` on signing and upload.** The Cosign signing and vault upload steps run even when the policy gate fails. A failure run produces a signed, locked failure bundle. This closes the argument that someone suppressed evidence of a bad change. Both the policy result and the gate outcome are preserved.

**Tight IAM inline policy on vault write.** The OIDC role has `ReadOnlyAccess` as its managed policy. The vault write permissions are a separate inline policy scoped to exactly five S3 actions on exactly one bucket ARN. The role cannot create buckets, delete objects, or touch any other AWS resource.

**Object Lock in GOVERNANCE mode for the lab.** GOVERNANCE mode allows a user with `s3:BypassGovernanceRetention` to remove the lock, which makes cleanup practical in a lab environment. In production this would be COMPLIANCE mode, which no AWS account can bypass before the retention date, including the root account.

**Receipt file alongside the bundle.** Every vault upload includes a `receipt.json` containing the run ID, vault name, S3 object key, S3 version ID, SHA-256 hash, and commit SHA. The version ID is what anchors the Object Lock. If someone disputes a run, the receipt points directly to the locked object version.

## Results

**Green PR** (`add-chain-of-custody`): All three policy namespaces passed. Cosign signed the bundle, Rekor logged the entry, bundle uploaded to vault. Merge allowed.

**Red PR** (`break-encryption`): SC-28 fired against `aws_s3_bucket.primary`. Merge blocked. The failure evidence was still signed by Cosign and uploaded to the vault. Running `verify-evidence.sh` against the red run returns `CHAIN INTACT` because the chain of custody holds for failure runs too.

**Tamper test:** The original bundle hash was `b126b6bc3ef8966f8d5148bf00f041af0cf29c82856a05bb34452c7a4ca13674`. After appending a single word to the downloaded copy the hash became `30eeff920b570a2484f539623fc70599315624c8104771912dc91848fe4c459f`. The verify script exits with `FAIL: SHA mismatch` at check 1. The vault copy is unchanged.

## How to Reproduce

**Prerequisites:** AWS account, GitHub repo, S3 Object Lock vault from Lab 2.5, AWS CLI configured locally, Cosign installed.

**1. Deploy the vault (Lab 2.5 Terraform):**
```bash
cd /path/to/cgep-lab-2.5/terraform/primitives/evidence-vault
terraform init
terraform apply -var="project_name=cgep-lab" -auto-approve
```
Note the `vault_name` output.

**2. Create the OIDC trust in AWS:**
```bash
cd oidc
terraform init
terraform apply -var="github_org=YOUR_ORG" -var="github_repo=YOUR_REPO" -auto-approve
```

**3. Grant the OIDC role write access to the vault:**
```bash
aws iam put-role-policy --role-name cgep-grc-gate --policy-name vault-write \
  --policy-document file://path/to/vault-write-policy.json
```

**4. Add GitHub repo variables:**
- `AWS_ROLE_ARN`: the role ARN from step 2
- `EVIDENCE_VAULT`: the bucket name from step 1

**5. Push the workflow to a branch and open a PR targeting `main`.** Signing and upload run automatically.

**6. Verify a run:**
```bash
export EVIDENCE_VAULT=your-vault-bucket-name
bash scripts/verify-evidence.sh YOUR_RUN_ID
```

**Cleanup:** Vault objects are locked for the retention period. After retention expires, delete the bucket. The IAM role and OIDC provider can stay in place for future labs.
