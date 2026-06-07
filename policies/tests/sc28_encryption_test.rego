# policies/tests/sc28_encryption_test.rego
package compliance.sc28_test

import rego.v1
import data.compliance.sc28

compliant_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.good",
		"type": "aws_s3_bucket",
		"values": {"bucket": "lab33-good-bucket"},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.good",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
	},
]}}}

aes256_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.bad",
		"type": "aws_s3_bucket",
		"values": {"bucket": "lab33-bad"},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.bad",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
	},
]}}}

no_sse_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.naked",
		"type": "aws_s3_bucket",
		"values": {"bucket": "lab33-naked"},
	},
]}}}

test_compliant_passes if { count(sc28.deny) == 0 with input as compliant_input }

test_aes256_fails if {
	some msg in sc28.deny with input as aes256_input
	contains(msg, "SC-28")
	contains(msg, "aws_s3_bucket.bad")
}

test_no_sse_fails if {
	some msg in sc28.deny with input as no_sse_input
	contains(msg, "SC-28")
	contains(msg, "aws_s3_bucket.naked")
}