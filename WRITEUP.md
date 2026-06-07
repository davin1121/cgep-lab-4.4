# Lab 4.4 Writeup: Evidence Chain of Custody

## The Four Chain of Custody Properties

### 1. Authenticity
**What it means:** The evidence was produced by the claimed source and has not been fabricated.

**What proves it:** The Cosign signature in `evidence-<run_id>-<sha>.tar.gz.sig.bundle`.

When the GitHub Actions workflow runs, it requests a short-lived certificate from Sigstore's Fulcio CA using the same OIDC token used to authenticate to AWS. That certificate contains the OIDC subject, which identifies the exact GitHub organization, repository, and workflow file that produced the signature. The certificate is logged in Sigstore's Rekor transparency log, which is a public append-only ledger not controlled by this AWS account or this GitHub organization.

An auditor can run `cosign verify-blob --bundle <bundle.sig.bundle> --certificate-oidc-issuer https://token.actions.githubusercontent.com <bundle.tar.gz>` and independently confirm the signature is valid without trusting anything I say.

---

### 2. Integrity
**What it means:** The evidence file has not been modified since it was created.

**What proves it:** The SHA-256 hash stored in `evidence-<run_id>-<sha>.tar.gz.sha256`.

The hash is computed in the CI workflow immediately after the bundle is created, before anything is uploaded. The hash file is uploaded to the vault alongside the bundle. When `verify-evidence.sh` runs, it recomputes the SHA-256 of the downloaded bundle and compares it to the stored hash. Any modification to any byte in the bundle, including adding a single character, produces a completely different hash.

**Tamper test result (run 27097937427):**
- Original hash: `b126b6bc3ef8966f8d5148bf00f041af0cf29c82856a05bb34452c7a4ca13674`
- After appending "tampered": `30eeff920b570a2484f539623fc70599315624c8104771912dc91848fe4c459f`
- Verify script result: `FAIL: SHA mismatch` (exit 1)

---

### 3. Timeliness
**What it means:** The evidence was created at the claimed point in time.

**What proves it:** The Rekor transparency log entry embedded in `evidence-<run_id>-<sha>.tar.gz.sig.bundle`.

When Cosign signs the bundle, Sigstore's Rekor log records the signing event with a timestamp from a trusted timestamping authority. That timestamp is included in the `.sig.bundle` file and verified during `cosign verify-blob`. The timestamp is not self-reported by the CI pipeline. It comes from a public authority outside this environment.

---

### 4. Preservation
**What it means:** The evidence cannot be deleted or altered before its retention period expires.

**What proves it:** S3 Object Lock on the vault bucket, confirmed by `get-object-retention` in step 3 of `verify-evidence.sh`.

The vault was deployed in GOVERNANCE mode with a 1-day default retention for lab purposes. In production this would be COMPLIANCE mode with a retention period matching the compliance framework requirement (typically 3 years for SOC 2, 6 years for HIPAA, 6 years for FedRAMP). Object Lock in COMPLIANCE mode cannot be removed even by the AWS root account before the retention date expires.

**Verification output for run 27097937427:**
```
=== 3. Preservation (Object Lock retention) ===
  OK (retain until 2026-06-08T16:16:08.393000+00:00)
```

---

## Full Verification Output (run 27097937427)

```
Downloading evidence bundle for run 27097937427...

=== 1. Integrity (SHA-256) ===
  OK (b126b6bc3ef8966f8d5148bf00f041af0cf29c82856a05bb34452c7a4ca13674)

=== 2. Authenticity + timestamp (Cosign + Sigstore Rekor) ===
Verified OK
  OK (Cosign verified, Rekor entry exists)

=== 3. Preservation (Object Lock retention) ===
  OK (retain until 2026-06-08T16:16:08.393000+00:00)

CHAIN INTACT for run 27097937427
```
