import json
import logging

import pytest
import yaml
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.panther import PantherSdyamlBackend
from sigma.collection import SigmaCollection


@pytest.fixture
def backend():
    return PantherSdyamlBackend()


def sigma_query(detection):
    return f"""
title: Test
logsource:
    product: test
detection:
    {detection}
"""


def matcher(key, condition, value=None):
    rv = {"KeyPath": key, "Condition": condition}

    if value:
        rv["Value"] = value

    return rv


def matcher_equals(key, value):
    return matcher(key, "Equals", value)


def matcher_does_not_equal(key, value):
    return matcher(key, "DoesNotEqual", value)


def matcher_starts_with(key, value):
    return matcher(key, "StartsWith", value)


def matcher_is_in(key, values):
    return {
        "KeyPath": key,
        "Condition": "IsIn",
        "Values": values,
    }


def matcher_ends_with(key, value):
    return matcher(key, "EndsWith", value)


def matcher_exists(key):
    return matcher(key, "Exists")


def execute_test(backend, sigma_detection_input, expected_obj_or_str):
    sigma_input = sigma_query(sigma_detection_input.strip())
    logging.debug("> Sigma Input:")
    logging.debug(sigma_input.strip())
    actual = backend.convert(SigmaCollection.from_yaml(sigma_input))

    logging.debug("> Actual (JSON):")
    logging.debug(json.dumps(actual))

    logging.debug("> Actual (YAML):")
    logging.debug(yaml.dump(actual))

    expected = expected_obj_or_str
    if isinstance(expected_obj_or_str, str):
        expected = [yaml.safe_load(expected_obj_or_str)]

    logging.debug("> Expected (YAML):")
    logging.debug(yaml.dump(expected))

    assert actual == yaml.dump(expected)


def test_implicit_and(backend):
    sigma_detection_input = """
    selection:
        fieldA: valueA
        fieldB: valueB
        fieldC: valueC
    condition: selection
    """

    expected = [{
        "All": [
            matcher_equals("fieldA", "valueA"),
            matcher_equals("fieldB", "valueB"),
            matcher_equals("fieldC", "valueC"),
        ]
    }]

    execute_test(backend, sigma_detection_input, expected)


def test_implicit_or(backend):
    sigma_detection_input = """
    selection:
        fieldA:
            - valueA
            - valueB
            - valueC
    condition: selection
    """

    expected = [
        matcher_is_in("fieldA", ["valueA", "valueB", "valueC"]),
    ]

    execute_test(backend, sigma_detection_input, expected)


def test_condition_and(backend):
    sigma_detection_input = """
    selection:
        fieldA: valueA
    filter:
        fieldB: valueB
    condition: selection and filter
    """

    expected = [{
        "All": [
            matcher_equals("fieldA", "valueA"),
            matcher_equals("fieldB", "valueB"),
        ]
    }]

    execute_test(backend, sigma_detection_input, expected)


def test_condition_and__with_implicit_and(backend):
    sigma_detection_input = """
    selection:
        fieldA1: valueA1
        fieldA2: valueA2
    filter:
        fieldB: valueB
    condition: selection and filter
    """

    expected = [
        {
            "All":
                [
                    {
                        "All": [
                            matcher_equals("fieldA1", "valueA1"),
                            matcher_equals("fieldA2", "valueA2"),
                        ]
                    },
                    matcher_equals("fieldB", "valueB"),
                ]
        }
    ]

    execute_test(backend, sigma_detection_input, expected)


def test_condition_and__with_implicit_or(backend):
    sigma_detection_input = """
    selection:
        fieldA1:
            - valueA1
            - valueA2
    filter:
        fieldB: valueB
    condition: selection and filter
    """

    expected = [{
        "All": [
            matcher_is_in("fieldA1", ["valueA1", "valueA2"]),
            matcher_equals("fieldB", "valueB"),
        ]
    }]

    execute_test(backend, sigma_detection_input, expected)


def test_condition_and__with_condition_not(backend):
    sigma_detection_input = """
    selection:
        fieldA: valueA
    filter:
        fieldB: valueB
    condition: selection and not filter
    """

    expected = [{
        "All": [
            matcher_equals("fieldA", "valueA"),
            matcher_does_not_equal("fieldB", "valueB"),
        ]
    }]

    execute_test(backend, sigma_detection_input, expected)


def test_condition_not_one_of(backend):
    sigma_detection_input = """
    filter1:
        fieldA: valueA
    filter2:
        fieldB: valueB
    condition: not 1 of filter*
    """

    expected = [{
        "All": [
            matcher_does_not_equal("fieldA", "valueA"),
            matcher_does_not_equal("fieldB", "valueB"),
        ]
    }]

    execute_test(backend, sigma_detection_input, expected)


def test_string_contains_asterisk(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_ec2_vm_export_failure.yml"""

    sigma_detection_input = """
    selection:
        fieldA|contains: '*'
    condition: selection
    """

    expected = """
      'KeyPath': 'fieldA'
      'Condition': 'Exists'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_one_wildcard_in_middle(backend):
    sigma_detection_input = """
    selection:
        fieldA: abc*123
    condition: selection
    """

    expected = [{
        "All": [
            matcher_starts_with("fieldA", "abc"),
            matcher_ends_with("fieldA", "123"),
        ]
    }]

    execute_test(backend, sigma_detection_input, expected)


# Real rules
# https://www.notion.so/pantherlabs/Sigma-SDYAML-Detection-Parity-6abef8d18c964477b14f41859cb89161


def test_okta_policy_rule_modified_or_deleted(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/okta/okta_policy_rule_modified_or_deleted.yml"""

    sigma_detection_input = """
    selection:
        eventtype:
            - policy.rule.update
            - policy.rule.delete
    condition: selection
    """

    expected = """
    KeyPath: eventtype
    Condition: IsIn
    Values:
        - policy.rule.update
        - policy.rule.delete
    """

    execute_test(backend, sigma_detection_input, expected)


def test_okta_fastpass_phishing_detection(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/okta/okta_fastpass_phishing_detection.yml"""

    sigma_detection_input = """
    selection:
        outcome.reason: 'FastPass declined phishing attempt'
        outcome.result: FAILURE
        eventtype: user.authentication.auth_via_mfa
    condition: selection
    """

    expected = """
    All: # selection implicit AND
        - KeyPath: outcome.reason
          Condition: Equals
          Value: 'FastPass declined phishing attempt'
        - KeyPath: outcome.result
          Condition: Equals
          Value: FAILURE
        - KeyPath: eventtype
          Condition: Equals
          Value: user.authentication.auth_via_mfa
    """

    execute_test(backend, sigma_detection_input, expected)


def test_aws_attached_malicious_lambda_layer(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_attached_malicious_lambda_layer.yml"""

    sigma_detection_input = """
    selection:
        eventSource: lambda.amazonaws.com
        eventName|startswith: 'UpdateFunctionConfiguration'
    condition: selection
    """

    expected = """
    All: # selection implicit AND
        - KeyPath: eventSource
          Condition: Equals
          Value: lambda.amazonaws.com
        - KeyPath: eventName
          Condition: StartsWith
          Value: UpdateFunctionConfiguration
    """

    execute_test(backend, sigma_detection_input, expected)


def test_aws_cloudtrail_important_change(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_cloudtrail_disable_logging.yml"""

    sigma_detection_input = """
    selection_source:
        eventSource: cloudtrail.amazonaws.com
        eventName:
            - StopLogging
            - UpdateTrail
            - DeleteTrail
    condition: selection_source
    """

    expected = """
    All: #selection_source implicit AND
        - KeyPath: eventSource
          Condition: Equals
          Value: 'cloudtrail.amazonaws.com'
        - KeyPath: eventName
          Condition: IsIn
          Values:
              - StopLogging
              - UpdateTrail
              - DeleteTrail
    """

    execute_test(backend, sigma_detection_input, expected)


def test_aws_ec2_vm_export_failure(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_ec2_vm_export_failure.yml"""

    sigma_detection_input = """
    selection:
        eventName: 'CreateInstanceExportTask'
        eventSource: 'ec2.amazonaws.com'
    filter1:
        errorMessage|contains: '*'
    filter2:
        errorCode|contains: '*'
    filter3:
        responseElements|contains: 'Failure'
    condition: selection and not 1 of filter*
    """

    expected = """
    All: # [selection] and [not 1 of filter*]
        - All: # selection implicit AND
            - KeyPath: eventName
              Condition: Equals
              Value: 'CreateInstanceExportTask'
            - KeyPath: eventSource
              Condition: Equals
              Value: 'ec2.amazonaws.com'
        - All:
            # not filter1
            - KeyPath: errorMessage
              Condition: DoesNotExist
            # not filter2
            - KeyPath: errorCode
              Condition: DoesNotExist
            # not filter3
            - KeyPath: responseElements
              Condition: DoesNotContain
              Value: 'Failure'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_potential_bucket_enumeration_on_aws(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_enum_buckets.yml"""

    sigma_detection_input = """
    selection:
        eventSource: 's3.amazonaws.com'
        eventName: 'ListBuckets'
    filter:
        type: 'AssumedRole'
    condition: selection and not filter
    """

    expected = """
    All: # [selection] and [not filter]
        - All: # selection implicit AND
            - KeyPath: eventSource
              Condition: Equals
              Value: 's3.amazonaws.com'
            - KeyPath: eventName
              Condition: Equals
              Value: 'ListBuckets'
        # not filter
        - KeyPath: type
          Condition: DoesNotEqual
          Value: 'AssumedRole'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_aws_suspicious_saml_activity(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_susp_saml_activity.yml"""

    sigma_detection_input = """
    selection_sts:
        eventSource: 'sts.amazonaws.com'
        eventName: 'AssumeRoleWithSAML'
    selection_iam:
        eventSource: 'iam.amazonaws.com'
        eventName: 'UpdateSAMLProvider'
    condition: 1 of selection_*
    """

    expected = """
    Any: # 1 of selection_*
        - All: # selection_sts implicit AND
            - KeyPath: eventSource
              Condition: Equals
              Value: 'sts.amazonaws.com'
            - KeyPath: eventName
              Condition: Equals
              Value: 'AssumeRoleWithSAML'
        - All: # selection_iam implicit AND
            - KeyPath: eventSource
              Condition: Equals
              Value: 'iam.amazonaws.com'
            - KeyPath: eventName
              Condition: Equals
              Value: 'UpdateSAMLProvider'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_pst_export_alert_using_new_compliancesearchaction(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/microsoft365_pst_export_alert_using_new_compliancesearchaction.yml"""

    sigma_detection_input = """
    selection:
        eventSource: SecurityComplianceCenter
        Payload|contains|all:
            - 'New-ComplianceSearchAction'
            - 'Export'
            - 'pst'
    condition: selection
    """

    expected = """
    All: # selection implicit AND
        - KeyPath: eventSource
          Condition: Equals
          Value: 'SecurityComplianceCenter'
        - All: # Payload|contains|all
            - KeyPath: Payload
              Condition: Contains
              Value: 'New-ComplianceSearchAction'
            - KeyPath: Payload
              Condition: Contains
              Value: 'Export'
            - KeyPath: Payload
              Condition: Contains
              Value: 'pst'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_google_cloud_kubernetes_admission_controller(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gcp/gcp_kubernetes_admission_controller.yml"""

    sigma_detection_input = """
    selection:
        gcp.audit.method_name|startswith: 'admissionregistration.k8s.io.v'
        gcp.audit.method_name|contains:
            - '.mutatingwebhookconfigurations.'
            - '.validatingwebhookconfigurations.'
        gcp.audit.method_name|endswith:
            - 'create'
            - 'patch'
            - 'replace'
    condition: selection
    """

    expected = """
    All: # selection implicit AND
        - KeyPath: gcp.audit.method_name
          Condition: StartsWith
          Value: 'admissionregistration.k8s.io.v'
        - Any: # gcp.audit.method_name|contains
            - KeyPath: gcp.audit.method_name
              Condition: Contains
              Value: '.mutatingwebhookconfigurations.'
            - KeyPath: gcp.audit.method_name
              Condition: Contains
              Value: '.validatingwebhookconfigurations.'
        - Any: # gcp.audit.method_name|endswith
            - KeyPath: gcp.audit.method_name
              Condition: EndsWith
              Value: 'create'
            - KeyPath: gcp.audit.method_name
              Condition: EndsWith
              Value: 'patch'
            - KeyPath: gcp.audit.method_name
              Condition: EndsWith
              Value: 'replace'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_google_cloud_kubernetes_cronjob(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gcp/gcp_kubernetes_cronjob.yml"""

    sigma_detection_input = """
    selection:
        gcp.audit.method_name:
            - io.k8s.api.batch.v*.Job
            - io.k8s.api.batch.v*.CronJob
    condition: selection
    """

    expected = """
    Any: # selection implicit AND
        - All: # io.k8s.api.batch.v*.Job
            - KeyPath: gcp.audit.method_name
              Condition: StartsWith
              Value: 'io.k8s.api.batch.v'
            - KeyPath: gcp.audit.method_name
              Condition: EndsWith
              Value: '.Job'
        - All: # io.k8s.api.batch.v*.CronJob
            - KeyPath: gcp.audit.method_name
              Condition: StartsWith
              Value: 'io.k8s.api.batch.v'
            - KeyPath: gcp.audit.method_name
              Condition: EndsWith
              Value: '.CronJob'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_user_added_to_admin_group_macos(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_add_to_admin_group.yml"""

    sigma_detection_input = """
    selection_sysadminctl:
        Image|endswith: '/sysadminctl'
        CommandLine|contains|all:
            - ' -addUser '
            - ' -admin '
    selection_dscl:
        Image|endswith: '/dscl'
        CommandLine|contains|all:
            - ' -append '
            - ' /Groups/admin '
            - ' GroupMembership '
    condition: 1 of selection_*
    """

    expected = """
    Any: # 1 of selection_*
        - All: # selection_sysadminctl implicit AND
            - KeyPath: Image
              Condition: EndsWith
              Value: '/sysadminctl'
            - All: # CommandLine|contains|all
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: ' -addUser '
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: ' -admin '
        - All: # selection_dscl implicit AND
            - KeyPath: Image
              Condition: EndsWith
              Value: '/dscl'
            - All: # CommandLine|contains|all
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: ' -append '
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: ' /Groups/admin '
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: ' GroupMembership '
    """

    execute_test(backend, sigma_detection_input, expected)


def test_jxa_in_memory_execution_via_osascript(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.yml"""

    sigma_detection_input = """
    selection_main:
        CommandLine|contains|all:
            - 'osascript'
            - ' -e '
            - 'eval'
            - 'NSData.dataWithContentsOfURL'
    selection_js:
        - CommandLine|contains|all:
            - ' -l '
            - 'JavaScript'
        - CommandLine|contains: '.js'
    condition: all of selection_*
    """

    expected = """
    All: # all of selection_*
        - All: # CommandLine|contains|all
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: 'osascript'
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: ' -e '
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: 'eval'
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: 'NSData.dataWithContentsOfURL'
        - Any: # selection_js implicit OR
                - All: # CommandLine|contains|all
                    - KeyPath: CommandLine
                      Condition: Contains
                      Value: ' -l '
                    - KeyPath: CommandLine
                      Condition: Contains
                      Value: 'JavaScript'
                - KeyPath: CommandLine
                  Condition: Contains
                  Value: '.js'
    """

    execute_test(backend, sigma_detection_input, expected)


def test_convert_condition_field_eq_val_null(backend):
    sigma_detection_input = """
    selection:
        - CommandLine: null
    condition: selection
    """

    expected = """
    KeyPath: CommandLine
    Condition: IsNull
    """

    execute_test(backend, sigma_detection_input, expected)


def test_convert_convert_condition_field_eq_val_num(backend):
    sigma_detection_input = """
    selection:
        dst_port:
            - 80
            - 8080
            - 21
    condition: selection
    """

    expected = [matcher_is_in("dst_port", [80, 8080, 21])]
    execute_test(backend, sigma_detection_input, expected)


def test_convert_condition_field_eq_val_re(backend):
    sigma_detection_input = """
    selection:
        - CommandLine|re: '"(\\{\\d\\})+"\\s*-f'
    condition: selection
    """

    expected = [{
        "All": [
            matcher_starts_with("fieldA", "abc"),
            matcher_ends_with("fieldA", "123"),
        ]
    }]
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        execute_test(backend, sigma_detection_input, expected)
