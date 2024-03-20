import json
import logging

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.panther import PantherBackend


def convert_rule(rule):
    return PantherBackend().convert(
        rule_collection=SigmaCollection.from_yaml(sigma_query(rule)), output_format="python"
    )


@pytest.fixture
def backend():
    return PantherBackend()


def sigma_query(detection):
    return f"""
title: Test
logsource:
    product: test
detection:
    {detection}
"""


def test_implicit_and(backend):
    sigma_detection_input = """
    selection:
        fieldA: valueA
        fieldB: valueB
        fieldC: valueC
    condition: selection
    """
    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if all(
        [
            deep_get(event, "fieldA") == "valueA",
            deep_get(event, "fieldB") == "valueB",
            deep_get(event, "fieldC") == "valueC",
        ]
    ):
        return True
    return False
"""

    result = convert_rule(sigma_detection_input)
    assert str(result) == expected_result


def test_implicit_or(backend):
    rule = """
    selection:
        fieldA:
            - valueA
            - valueB
            - valueC
    condition: selection
    """
    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "fieldA") in ["valueA", "valueB", "valueC"]:
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_and(backend):
    rule = """
    selection:
        fieldA: valueA
    filter:
        fieldB: valueB
    condition: selection and filter
    """

    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if all([deep_get(event, "fieldA") == "valueA", deep_get(event, "fieldB") == "valueB"]):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_and__with_implicit_and(backend):
    rule = """
    selection:
        fieldA1: valueA1
        fieldA2: valueA2
    filter:
        fieldB: valueB
    condition: selection and filter
    """

    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if all(
        [
            deep_get(event, "fieldA1") == "valueA1",
            deep_get(event, "fieldA2") == "valueA2",
            deep_get(event, "fieldB") == "valueB",
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_and__with_implicit_or(backend):
    rule = """
    selection:
        fieldA1:
            - valueA1
            - valueA2
    filter:
        fieldB: valueB
    condition: selection and filter
    """
    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if all(
        [
            deep_get(event, "fieldA1") in ["valueA1", "valueA2"],
            deep_get(event, "fieldB") == "valueB",
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_and__with_condition_not(backend):
    rule = """
    selection:
        fieldA: valueA
    filter:
        fieldB: valueB
    condition: selection and not filter
    """
    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if all([deep_get(event, "fieldA") == "valueA", not deep_get(event, "fieldB") == "valueB"]):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_not_one_of(backend):
    rule = """
    filter1:
        fieldA: valueA
    filter2:
        fieldB: valueB
    condition: not 1 of filter*
    """
    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if all([not deep_get(event, "fieldA") == "valueA", not deep_get(event, "fieldB") == "valueB"]):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_string_contains_asterisk(backend):
    """https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_ec2_vm_export_failure.yml"""

    rule = """
    selection:
        fieldA|contains: '*'
    condition: selection
    """

    expected_result = """from panther_base_helpers import deep_get
import re


def rule(event):
    if re.match(".*", deep_get(event, "fieldA")):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_one_wildcard_in_middle(backend):
    rule = """
    selection:
        fieldA: abc*123
    condition: selection
    """

    expected_result = """from panther_base_helpers import deep_get
import re


def rule(event):
    if re.match("abc.*123", deep_get(event, "fieldA")):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_convert_condition_field_eq_val_null():
    rule = """
    selection:
        - CommandLine: null
    condition: selection
    """

    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "CommandLine") is None:
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_convert_convert_condition_field_eq_val_num():
    rule = """
    selection:
        dst_port:
            - 80
            - 8080
            - 21
    condition: selection
    """
    expected_result = """from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "dst_port") in [80, 8080, 21]:
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_convert_condition_field_eq_val_re(backend):
    rule = """
    selection:
        - ImagePath|re: '^[Cc]:\\[Pp]rogram[Dd]ata\\.{1,9}\.exe'
    condition: selection
    """

    expected_result = """from panther_base_helpers import deep_get
import re


def rule(event):
    if re.match("^[Cc]:\\[Pp]rogram[Dd]ata\\.{1,9}\\.exe", deep_get(event, "ImagePath")):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result
