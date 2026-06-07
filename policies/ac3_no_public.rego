# policies/ac3_no_public.rego
# METADATA
# title: "AC-3 - Access Enforcement (S3 public access + open security groups)"
# description: "S3 buckets must have all four public access block flags set to true. Security groups must not expose ports 22 or 3389 to 0.0.0.0/0."
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: "Set all four block flags to true in aws_s3_bucket_public_access_block. For security groups, narrow cidr_blocks or remove the rule."
package compliance.ac3

import rego.v1

# --- S3 Buckets ---

deny contains msg if {
	some bucket in all_resources
	bucket.type == "aws_s3_bucket"
	bucket_name := resource_name(bucket.address)
	not bucket_name in fully_blocked_names
	msg := sprintf(
		"[AC-3] %s: public access not fully blocked. Remediation: add aws_s3_bucket_public_access_block with all four flags set to true.",
		[bucket.address],
	)
}

fully_blocked_names contains name if {
	some r in all_resources
	r.type == "aws_s3_bucket_public_access_block"
	r.values.block_public_acls == true
	r.values.block_public_policy == true
	r.values.ignore_public_acls == true
	r.values.restrict_public_buckets == true
	name := resource_name(r.address)
}

# --- Security Groups ---

mgmt_port(p) if p == 22
mgmt_port(p) if p == 3389

deny contains msg if {
	some r in all_resources
	r.type == "aws_security_group"
	some ingress in r.values.ingress
	some cidr in ingress.cidr_blocks
	cidr == "0.0.0.0/0"
	mgmt_port(ingress.from_port)
	msg := sprintf(
		"[AC-3] %s: management port %d open to %s. Remediation: narrow cidr_blocks or remove the ingress rule.",
		[r.address, ingress.from_port, cidr],
	)
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