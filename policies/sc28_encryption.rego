# policies/sc28_encryption.rego
# METADATA
# title: "SC-28 - Encryption at Rest (S3)"
# description: "Every aws_s3_bucket must have a corresponding aws_s3_bucket_server_side_encryption_configuration using aws:kms."
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\" for each bucket."
package compliance.sc28

import rego.v1

deny contains msg if {
	some bucket in all_resources
	bucket.type == "aws_s3_bucket"
	bucket_name := resource_name(bucket.address)
	not bucket_name in kms_encrypted_names
	msg := sprintf(
		"[SC-28] %s: missing KMS encryption. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\".",
		[bucket.address],
	)
}

kms_encrypted_names contains name if {
	some r in all_resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some rule in r.values.rule
	rule.apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
	name := resource_name(r.address)
}

all_resources contains r if { some r in input.planned_values.root_module.resources }
all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

resource_name(address) := name if {
	parts := split(address, ".")
	name := parts[count(parts) - 1]
}