import json
from pathlib import Path

import parliament
from checkov.common.models.enums import (
    CheckCategories,
    CheckResult,
)
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from parliament.cli import is_finding_filtered


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


class ParliamentIAMPolicyProblem(BaseResourceCheck):

    def __init__(self):
        name = "duo-labs/parliament issue(s) found"
        self.base_name = "duo-labs/parliament issue(s) found"
        id = "CKV_AWS_9999"
        categories = [CheckCategories.IAM]
        supported_resources = ['aws_iam_policy']
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf):
        """
        Check aws_iam_policy_document documents with duo-labs/parliament
            https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy
            https://github.com/duo-labs/parliament

        :param conf: aws_iam_policy configuration
        :return: <CheckResult>
        """
        # We change the name only if we find issues
        self.name = self.base_name

        policy_string = conf['policy'][0].strip()
        # For e.g. 'policy = "{\"Version\":...' (as opposed to 'policy = <<EOF...')
        policy_string = policy_string.replace('\\"', '"')

        # For ignoring e.g. 'policy = "${data.aws_iam_policy_document...'
        if policy_string.startswith('${data.aws_iam_policy_document.'):
            return CheckResult.PASSED

        try:
            json.loads(policy_string)
        except ValueError:
            return CheckResult.PASSED

        parliament_findings_summary = get_parliament_findings_summary(policy_string=policy_string)
        print(f"parliament_findings_summary is {parliament_findings_summary}")
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
check = ParliamentIAMPolicyProblem()
