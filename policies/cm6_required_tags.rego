# policies/cm6_required_tags.rego
# METADATA
# title: "CM-6 - Configuration Settings (required tags)"
# description: "Every taggable resource must carry the four required tags: project, environment, managed_by, compliance_scope."
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
#   remediation: "Add the four required tags (project, environment, managed_by, compliance_scope) to the resource."
package compliance.cm6

import rego.v1

required := {"project", "environment", "managed_by", "compliance_scope"}

taggable_type(t) if t == "aws_s3_bucket"
taggable_type(t) if t == "aws_instance"
taggable_type(t) if t == "aws_ebs_volume"

deny contains msg if {
	some resource in all_resources
	taggable_type(resource.type)
	provided := provided_tags(resource)
	missing := required - provided
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required tags %v. Remediation: add the missing tags to the resource.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if { some r in input.planned_values.root_module.resources }
all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

provided_tags(resource) := keys if {
	resource.values.tags
	keys := {k | resource.values.tags[k]}
}

provided_tags(resource) := set() if { not resource.values.tags }

sort_array(s) := sorted if { sorted := sort([x | some x in s]) }