import pytest
from sigma.collection import SigmaCollection

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import carbon_black_panther_pipeline


def convert_rule(rule, pipeline=None):
    return PantherBackend(pipeline).convert(
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
    expected_result = """def rule(event):
    if all(
        [
            event.deep_get("fieldA", default="") == "valueA",
            event.deep_get("fieldB", default="") == "valueB",
            event.deep_get("fieldC", default="") == "valueC",
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
    expected_result = """def rule(event):
    if event.deep_get("fieldA", default="") in ["valueA", "valueB", "valueC"]:
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

    expected_result = """def rule(event):
    if all(
        [
            event.deep_get("fieldA", default="") == "valueA",
            event.deep_get("fieldB", default="") == "valueB",
        ]
    ):
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

    expected_result = """def rule(event):
    if all(
        [
            event.deep_get("fieldA1", default="") == "valueA1",
            event.deep_get("fieldA2", default="") == "valueA2",
            event.deep_get("fieldB", default="") == "valueB",
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
    expected_result = """def rule(event):
    if all(
        [
            event.deep_get("fieldA1", default="") in ["valueA1", "valueA2"],
            event.deep_get("fieldB", default="") == "valueB",
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
    expected_result = """def rule(event):
    if all(
        [
            event.deep_get("fieldA", default="") == "valueA",
            not event.deep_get("fieldB", default="") == "valueB",
        ]
    ):
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
    expected_result = """def rule(event):
    if not any(
        [
            event.deep_get("fieldA", default="") == "valueA",
            event.deep_get("fieldB", default="") == "valueB",
        ]
    ):
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

    expected_result = """def rule(event):
    if event.deep_get("fieldA", default="") != "":
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

    expected_result = """import re


def rule(event):
    if re.match(r"^abc.*123$", event.deep_get("fieldA", default="")):
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

    expected_result = """def rule(event):
    if event.deep_get("CommandLine", default="") == "":
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
    expected_result = """def rule(event):
    if event.deep_get("dst_port", default="") in [80, 8080, 21]:
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

    expected_result = """import re


def rule(event):
    if re.match(r"^[Cc]:\\[Pp]rogram[Dd]ata\\.{1,9}\\.exe", event.deep_get("ImagePath", default="")):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_endswith(backend):
    rule = """
    selection:
        fieldA|endswith: valueA
    condition: selection
    """

    expected_result = """def rule(event):
    if event.deep_get("fieldA", default="").endswith("valueA"):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_startswith(backend):
    rule = """
    selection:
        fieldA|startswith: valueA
    condition: selection
    """

    expected_result = """def rule(event):
    if event.deep_get("fieldA", default="").startswith("valueA"):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_contains(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    condition: selection
    """

    expected_result = """def rule(event):
    if "valueA" in event.deep_get("fieldA", default=""):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_contains_with_backslash(backend):
    rule = """
    selection:
        fieldA|contains: \\valueA\\valueB
    condition: selection
    """

    expected_result = """def rule(event):
    if "\\\\valueA\\\\valueB" in event.deep_get("fieldA", default=""):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_selection_and_not_filter(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    filter:
        Image:
            - 'qrs'
            - 'xyz'
        OriginalFileName:
            - 'abc'
            - 'efg'
    condition: selection and not filter
    """

    expected_result = """def rule(event):
    if all(
        [
            "valueA" in event.deep_get("fieldA", default=""),
            not all(
                [
                    event.deep_get("Image", default="") in ["qrs", "xyz"],
                    event.deep_get("OriginalFileName", default="") in ["abc", "efg"],
                ]
            ),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_selection_and_1_of_filter(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    filter_1:
        Image:
            - 'qrs'
            - 'xyz'
    filter_2:
        OriginalFileName:
            - 'abc'
            - 'efg'
    condition: selection and 1 of filter
    """

    expected_result = """def rule(event):
    if all(
        [
            "valueA" in event.deep_get("fieldA", default=""),
            any(
                [
                    event.deep_get("Image", default="") in ["qrs", "xyz"],
                    event.deep_get("OriginalFileName", default="") in ["abc", "efg"],
                ]
            ),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_selection_and_not_1_of_filter(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    filter_1:
        Image:
            - 'qrs'
            - 'xyz'
    filter_2:
        OriginalFileName:
            - 'abc'
            - 'efg'
    condition: selection and not 1 of filter
    """

    expected_result = """def rule(event):
    if all(
        [
            "valueA" in event.deep_get("fieldA", default=""),
            not any(
                [
                    event.deep_get("Image", default="") in ["qrs", "xyz"],
                    event.deep_get("OriginalFileName", default="") in ["abc", "efg"],
                ]
            ),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_selection_and_not_all_of_filter(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    filter_1:
        Image:
            - 'qrs'
            - 'xyz'
    filter_2:
        OriginalFileName:
            - 'abc'
            - 'efg'
    condition: selection and not all of filter
    """

    expected_result = """def rule(event):
    if all(
        [
            "valueA" in event.deep_get("fieldA", default=""),
            not all(
                [
                    event.deep_get("Image", default="") in ["qrs", "xyz"],
                    event.deep_get("OriginalFileName", default="") in ["abc", "efg"],
                ]
            ),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_selection_and_not_1_of_filter_main(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    filter_main_1:
        Image_1:
            - 'qrs'
            - 'xyz'
    filter_main_2:
        Image_2:
            - 'qrst'
            - 'xyza'
    filter_not_main:
        OriginalFileName_1:
            - 'abc'
            - 'efg'
        OriginalFileName_2:
            - 'abcd'
            - 'efgh'
    condition: selection and not 1 of filter_main_* and not filter_not_main
    """

    expected_result = """def rule(event):
    if all(
        [
            "valueA" in event.deep_get("fieldA", default=""),
            not any(
                [
                    event.deep_get("Image_1", default="") in ["qrs", "xyz"],
                    event.deep_get("Image_2", default="") in ["qrst", "xyza"],
                ]
            ),
            not all(
                [
                    event.deep_get("OriginalFileName_1", default="") in ["abc", "efg"],
                    event.deep_get("OriginalFileName_2", default="") in ["abcd", "efgh"],
                ]
            ),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_selection_or_not_filter(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    filter:
        Image:
            - 'qrs'
            - 'xyz'
        OriginalFileName:
            - 'abc'
            - 'efg'
    condition: selection or not filter
    """

    expected_result = """def rule(event):
    if any(
        [
            "valueA" in event.deep_get("fieldA", default=""),
            not all(
                [
                    event.deep_get("Image", default="") in ["qrs", "xyz"],
                    event.deep_get("OriginalFileName", default="") in ["abc", "efg"],
                ]
            ),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_1_of_selection(backend):
    rule = """
    selection_1:
        fieldA|contains: valueA
    selection_2:
        fieldB|contains: valueB
    condition: 1 of selection_*
    """

    expected_result = """def rule(event):
    if any(
        [
            "valueA" in event.deep_get("fieldA", default=""),
            "valueB" in event.deep_get("fieldB", default=""),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_pipeline_simplification(backend):
    rule = """
    selection_img:
        - Image|endswith: '\\bcdedit.exe'
        - OriginalFileName: 'bcdedit.exe'
    selection_set:
        CommandLine|contains: 'set'
    condition: all of selection_*
        """

    expected_result = """def rule(event):
    if all(
        [
            event.deep_get("process_path", default="").endswith("\\\\bcdedit.exe"),
            "set" in event.deep_get("target_cmdline", default=""),
        ]
    ):
        return True
    return False
"""

    result = convert_rule(rule, pipeline=carbon_black_panther_pipeline())
    assert result["Detection"][0] == expected_result
