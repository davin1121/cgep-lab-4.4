# policies/tests/ac3_no_public_test.rego
package compliance.ac3_test

import rego.v1
import data.compliance.ac3

compliant_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.good",
		"type": "aws_s3_bucket",
		"values": {"bucket": "good-bucket"},
	},
	{
		"address": "aws_s3_bucket_public_access_block.good",
		"type": "aws_s3_bucket_public_access_block",
		"values": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		},
	},
]}}}

public_bucket_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_s3_bucket.bad",
		"type": "aws_s3_bucket",
		"values": {"bucket": "bad-bucket"},
	},
	{
		"address": "aws_s3_bucket_public_access_block.bad",
		"type": "aws_s3_bucket_public_access_block",
		"values": {
			"block_public_acls": false,
			"block_public_policy": false,
			"ignore_public_acls": false,
			"restrict_public_buckets": false,
		},
	},
]}}}

open_sg_input := {"planned_values": {"root_module": {"resources": [
	{
		"address": "aws_security_group.open_ssh",
		"type": "aws_security_group",
		"values": {
			"ingress": [{
				"cidr_blocks": ["0.0.0.0/0"],
				"from_port": 22,
				"to_port": 22,
				"protocol": "tcp",
				"ipv6_cidr_blocks": [],
				"prefix_list_ids": [],
				"security_groups": [],
				"self": false,
				"description": "",
			}],
		},
	},
]}}}

test_compliant_bucket_passes if { count(ac3.deny) == 0 with input as compliant_input }

test_public_bucket_fails if {
	some msg in ac3.deny with input as public_bucket_input
	contains(msg, "AC-3")
	contains(msg, "aws_s3_bucket.bad")
}

test_open_sg_fails if {
	some msg in ac3.deny with input as open_sg_input
	contains(msg, "AC-3")
	contains(msg, "22")
}