import json
import re
from pathlib import Path

import parliament
from checkov.common.models.enums import (
    CheckCategories,
    CheckResult,
)
from checkov.terraform.checks.data.base_check import BaseDataCheck
from parliament.cli import is_finding_filtered


field_mappings = [
    {
        'tf_key': 'effect',
        'iam_key': 'Effect',
        'mock_value': 'Allow',
    },
    {
        'tf_key': 'actions',
        'iam_key': 'Action',
        'mock_value': '*',
    },
    {
        'tf_key': 'not_actions',
        'iam_key': 'NotAction',
        'mock_value': '*',
    },
    {
        'tf_key': 'resources',
        'iam_key': 'Resource',
        'mock_value': '*',
    },
    {
        'tf_key': 'not_resources',
        'iam_key': 'NotResource',
        'mock_value': '*',
    },
]


def mock_iam_statement_from_tf(tf_statement_data):
    """
    Creates a mock IAM statement from a TF definition,
    copying across only fields defined in the field_mappings
    and replacing TF interpolations "${var.xxx}"
    with mock vars for the field to pass validation
    """
    mock_iam_statement = {
        # Defaults to 'Allow' in Terraform
        'Effect': tf_statement_data.get('effect') or ['Allow'],
    }

    for field in field_mappings:
        if not tf_statement_data.get(field['tf_key']):
            continue

        field_values = tf_statement_data.get(field['tf_key'])[0]

        if isinstance(field_values, list):
            field_values = [
                re.sub(r'\${.*?}', field['mock_value'], field_value)
                for field_value in field_values
            ]
        # e.g. `'Allow'` in `'effect': ['Allow']`
        else:
            field_values = re.sub(r'\${.*?}', field['mock_value'], field_values)

        mock_iam_statement[field['iam_key']] = field_values

    print(f"mock_iam_statement is {mock_iam_statement}")
    # debuggin'
    if '${' in str(mock_iam_statement):
        import ipdb;ipdb.set_trace()

    return mock_iam_statement


# Do not want to share this between custom checks
# Will DRY once https://github.com/bridgecrewio/checkov/pull/716 is merged
def get_parliament_findings_summary(policy_string):
    """
    Returns None or a string like e.g.
        - PERMISSIONS_MANAGEMENT_ACTIONS - {'actions': ['ec2:resetsnapshotattribute', 'iam:passrole', 'ec2:createnetworkinterfacepermission', 'ec2:modifyvpcendpointservicepermissions', 'ec2:deletenetworkinterfacepermission', 'ec2:modifysnapshotattribute'], 'filepath': None}
        - PRIVILEGE_ESCALATION - {'type': 'CreateEC2WithExistingIP', 'actions': ['iam:passrole', 'ec2:runinstances'], 'filepath': None}
    """
    parliament_findings = [
        enhanced_finding
        for enhanced_finding in map(
            parliament.enhance_finding,
            parliament.analyze_policy_string(
                policy_string,
                include_community_auditors=True,
                config=parliament.config,
            ).findings,
        )
        if not(
            # Not a security issue
            # and ignore invalid e.g.
            #   "MALFORMED - Statement contains neither Resource nor NotResource"
            # findings
            enhanced_finding.issue == "MALFORMED"
            or
            is_finding_filtered(
                enhanced_finding,
                minimum_severity="MEDIUM",
            )
        )
    ]
    if parliament_findings:
        return (
            "- " + "\n- ".join(
                map(
                    str,
                    parliament_findings,
                )
            # For e.g. "PERMISSIONS_MANAGEMENT_ACTIONS -  - {'actions':"
            ).replace('-  -', '-')
        )


class ParliamentIAMPolicyDocumentProblem(BaseDataCheck):
    def __init__(self):
        name = "duo-labs/parliament issue(s) found"
        self.base_name = "duo-labs/parliament issue(s) found"
        id = "CKV_AWS_8888"
        categories = [CheckCategories.IAM]
        supported_data = ['aws_iam_policy_document']
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_data=supported_data,
        )

    def scan_data_conf(self, conf):
        """
        Check aws_iam_policy_document documents with duo-labs/parliament
            https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document
            https://github.com/duo-labs/parliament

        Note: This does not look at `source_json` or `override_json`.

        :param conf: aws_iam_policy_document configuration
        :return: <CheckResult>
        """
        # We change the name only if we find issues
        self.name = self.base_name

        # Statement is optional
        if 'statement' not in conf:
            return CheckResult.PASSED

        # What is in Terraform, is a subset of what is in a real IAM policy
        mock_iam_policy = {}
        try:
            mock_iam_policy['Version'] = conf['version'][0]
        except KeyError:
            # Version defaults to '2012-10-17' in Terraform
            mock_iam_policy['Version'] = '2012-10-17'
        mock_iam_policy['Statement'] = [
            mock_iam_statement_from_tf(statement)
            for statement in conf['statement']
        ]

        parliament_findings_summary = get_parliament_findings_summary(policy_string=json.dumps(mock_iam_policy))
        print(f"\nenhanced_filtered_findings are {parliament_findings_summary}")
        if parliament_findings_summary:
            self.name = f"{self.name}\n{parliament_findings_summary}"
            return CheckResult.FAILED
        return CheckResult.PASSED


# Do not want to share this between custom checks
# Will DRY once https://github.com/bridgecrewio/checkov/pull/716 is merged
def add_config_for_community_auditors():
    community_auditors_override_file = (
        Path(parliament.config_path).parent
        / "community_auditors"
        / "config_override.yaml"
    )
    # This adds to parliament.config
    parliament.override_config(community_auditors_override_file)


add_config_for_community_auditors()
check = ParliamentIAMPolicyDocumentProblem()
