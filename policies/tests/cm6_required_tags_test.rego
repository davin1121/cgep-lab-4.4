# policies/tests/cm6_required_tags_test.rego
package compliance.cm6_test

import rego.v1
import data.compliance.cm6

complete_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.good",
		"type": "aws_s3_bucket",
		"values": {"tags": {
			"project": "lab33",
			"environment": "dev",
			"managed_by": "terraform",
			"compliance_scope": "cge-p-lab",
		}},
	},
]}}}

missing_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.partial",
		"type": "aws_s3_bucket",
		"values": {"tags": {"project": "lab33"}},
	},
]}}}

no_tags_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.naked",
		"type": "aws_s3_bucket",
		"values": {},
	},
]}}}

test_complete_passes if { count(cm6.deny) == 0 with input as complete_input }

test_partial_fails if {
	some msg in cm6.deny with input as missing_input
	contains(msg, "CM-6")
	contains(msg, "aws_s3_bucket.partial")
}

test_no_tags_fails if {
	some msg in cm6.deny with input as no_tags_input
	contains(msg, "CM-6")
	contains(msg, "aws_s3_bucket.naked")
}