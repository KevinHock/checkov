import unittest

from checkov.terraform.checks.resource.aws.ParliamentIAMPolicyProblem import check
from checkov.common.models.enums import CheckResult


class TestParliamentIAMPolicyDocumentProblem(unittest.TestCase):

    def test_success_with_version(self):
        resource_conf = {
            'policy': [
                """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Action": [
                        "ec2:Describe*"
                      ],
                      "Effect": "Allow",
                      "Resource": "*"
                    }
                  ]
                }
                """
            ]
        }
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

    def test_permissions_management_actions_failure_with_no_version(self):
        resource_conf = {
            'policy': [
                """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Action": [
                        "s3:*"
                      ],
                      "Effect": "Allow",
                      "Resource": "*"
                    }
                  ]
                }
                """
            ]
        }
        scan_result = check.scan_resource_conf(conf=resource_conf)
        # Because 's3:*'
        self.assertTrue(check.name.count("- PERMISSIONS_MANAGEMENT_ACTIONS -") == 1)
        self.assertEqual(CheckResult.FAILED, scan_result)

    def test_privilege_escalation_failure(self):
        resource_conf = {
            'policy': [
                """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Action": [
                        "glue:updatedevendpoint",
                        "lambda:updatefunctioncode"
                      ],
                      "Effect": "Allow",
                      "Resource": "*"
                    }
                  ]
                }
                """
            ]
        }
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertTrue(check.name.count("duo-labs/parliament issue(s) found\n") == 1)
        # Because 'UpdateExistingGlueDevEndpoint' and 'EditExistingLambdaFunctionWithRole'
        self.assertTrue(check.name.count("- PRIVILEGE_ESCALATION -") == 2)
        self.assertEqual(CheckResult.FAILED, scan_result)

    def test_both_privilege_escalation_and_permissions_management_actions_failures(self):
        resource_conf = {
            'policy': [
                """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Action": [
                        "iam:PassRole",
                        "ec2:*"
                      ],
                      "Effect": "Allow",
                      "Resource": "*"
                    }
                  ]
                }
                """
            ]
        }
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertTrue(check.name.count("duo-labs/parliament issue(s) found\n") == 1)
        # Because 'ec2:*'
        self.assertTrue(check.name.count("- PERMISSIONS_MANAGEMENT_ACTIONS -") == 1)
        # Because 'CreateEC2WithExistingIP'
        self.assertTrue(check.name.count("- PRIVILEGE_ESCALATION -") == 1)
        self.assertEqual(CheckResult.FAILED, scan_result)


if __name__ == '__main__':
    unittest.main()
