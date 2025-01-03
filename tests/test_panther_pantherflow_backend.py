from unittest import mock

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import carbon_black_panther_pipeline


def convert_rule(rule, pipeline=None):
    return PantherBackend(pipeline).convert(
        rule_collection=SigmaCollection.from_yaml(sigma_query(rule)), output_format="pantherflow"
    )


@pytest.fixture
def backend():
    return PantherBackend()


def sigma_query(detection):
    return f"""
title: Test
logsource:
    category: process_creation
    product: macos
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
    expected_result = """ | where p_event_time > time.ago(1d)
 | where fieldA == 'valueA'
    and fieldB == 'valueB'
    and fieldC == 'valueC'
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
    expected_result = """ | where p_event_time > time.ago(1d)
 | where fieldA in ['valueA', 'valueB', 'valueC']
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where fieldA == 'valueA'
    and fieldB == 'valueB'
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where fieldA1 == 'valueA1'
    and fieldA2 == 'valueA2'
    and fieldB == 'valueB'
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
    expected_result = """ | where p_event_time > time.ago(1d)
 | where fieldA1 in ['valueA1', 'valueA2']
    and fieldB == 'valueB'
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
    expected_result = """ | where p_event_time > time.ago(1d)
 | where fieldA == 'valueA'
    and not (
      fieldB == 'valueB'
    )
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
    expected_result = """ | where p_event_time > time.ago(1d)
 | where not (
      (
        fieldA == 'valueA'
        or fieldB == 'valueB'
      )
    )
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where fieldA != ''
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_one_wildcard_in_middle(backend):
    rule = """
    selection:
        fieldA: abc*123
    condition: selection
    """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where re.matches(fieldA, '^abc.*123$')
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_convert_condition_field_eq_val_null():
    rule = """
    selection:
        - CommandLine: null
    condition: selection
    """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where CommandLine == ''
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
    expected_result = """ | where p_event_time > time.ago(1d)
 | where dst_port in [80, 8080, 21]
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_convert_condition_field_eq_val_re(backend):
    rule = """
    selection:
        - ImagePath|re: '^[Cc]:\\[Pp]rogram[Dd]ata\\.{1,9}\.exe'
    condition: selection
    """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where re.matches(ImagePath, '^[Cc]:\\\\[Pp]rogram[Dd]ata\\\\.{1,9}\\\\.exe')
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_endswith(backend):
    rule = """
    selection:
        fieldA|endswith: valueA
    condition: selection
    """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.ends_with(fieldA, 'valueA')
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_startswith(backend):
    rule = """
    selection:
        fieldA|startswith: valueA
    condition: selection
    """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.starts_with(fieldA, 'valueA')
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_contains(backend):
    rule = """
    selection:
        fieldA|contains: valueA
    condition: selection
    """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.contains(fieldA, 'valueA')
"""

    result = convert_rule(rule)
    assert result == expected_result


def test_condition_contains_with_backslash(backend):
    rule = """
    selection:
        fieldA|contains: \\valueA\\valueB
    condition: selection
    """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.contains(fieldA, '\\\\valueA\\\\valueB')
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.contains(fieldA, 'valueA')
    and not (
      Image in ['qrs', 'xyz']
      and OriginalFileName in ['abc', 'efg']
    )
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.contains(fieldA, 'valueA')
    and (
      Image in ['qrs', 'xyz']
      or OriginalFileName in ['abc', 'efg']
    )
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.contains(fieldA, 'valueA')
    and not (
      (
        Image in ['qrs', 'xyz']
        or OriginalFileName in ['abc', 'efg']
      )
    )
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.contains(fieldA, 'valueA')
    and not (
      Image in ['qrs', 'xyz']
      and OriginalFileName in ['abc', 'efg']
    )
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where strings.contains(fieldA, 'valueA')
    and not (
      (
        Image_1 in ['qrs', 'xyz']
        or Image_2 in ['qrst', 'xyza']
      )
    )
    and not (
      OriginalFileName_1 in ['abc', 'efg']
      and OriginalFileName_2 in ['abcd', 'efgh']
    )
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where (
      strings.contains(fieldA, 'valueA')
      or not (
        Image in ['qrs', 'xyz']
        and OriginalFileName in ['abc', 'efg']
      )
    )
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

    expected_result = """ | where p_event_time > time.ago(1d)
 | where (
      strings.contains(fieldA, 'valueA')
      or strings.contains(fieldB, 'valueB')
    )
"""

    result = convert_rule(rule)
    assert result == expected_result


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_pipeline_simplification(mock_click, backend):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "carbon_black_panther"}
    )
    rule = """
    selection_img:
        - Image|endswith: '\\bcdedit.exe'
        - OriginalFileName: 'bcdedit.exe'
    selection_set:
        CommandLine|contains: 'set'
    condition: all of selection_*
        """

    expected_result = """ | where p_event_time > time.ago(1d)
 | where type == 'endpoint.event.procstart'
    and device_os == 'MAC'
    and strings.ends_with(process_path, '\\\\bcdedit.exe')
    and strings.contains(target_cmdline, 'set')
"""

    result = convert_rule(rule, pipeline=carbon_black_panther_pipeline())
    assert result["Detection"][0] == expected_result
