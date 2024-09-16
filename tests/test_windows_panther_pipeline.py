import uuid
from unittest import mock

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import (
    windows_audit_panther_pipeline,
    windows_logsource_panther_pipeline,
)


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_windows_audit_basic_sdyaml(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "windows_audit_panther"}
    )
    resolver = ProcessingPipelineResolver(
        {"windows_audit_panther": windows_audit_panther_pipeline()}
    )
    pipeline = resolver.resolve_pipeline("windows_audit_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Details: "banana"
                CommandLine: "cmdline_test"
                Image: "test_image"
            condition: sel
    """
    )

    expected = yaml.dump(
        {
            "Description": "description",
            "AnalysisType": "rule",
            "DisplayName": "Test Title",
            "Enabled": True,
            "LogTypes": ["Windows.EventLogs"],
            "Tags": ["Sigma"],
            "Detection": [
                {
                    "All": [
                        {
                            "Condition": "Equals",
                            "KeyPath": "EventID",
                            "Value": 4688,
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "ExtraEventData.NewValue",
                            "Value": "banana",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "ExtraEventData.CommandLine",
                            "Value": "cmdline_test",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "ExtraEventData.NewProcessName",
                            "Value": "test_image",
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule, output_format="sdyaml") == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_windows_audit_basic_python(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "windows_audit_panther"}
    )
    resolver = ProcessingPipelineResolver(
        {"windows_audit_panther": windows_audit_panther_pipeline()}
    )
    pipeline = resolver.resolve_pipeline("windows_audit_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
            title: Test Title
            id: {rule_id}
            description: description
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Details: "banana"
                    CommandLine: "cmdline_test"
                    Image: "test_image"
                condition: sel
        """
    )

    expected = {
        "Description": "description",
        "AnalysisType": "rule",
        "DisplayName": "Test Title",
        "Enabled": True,
        "LogTypes": ["Windows.EventLogs"],
        "Tags": ["Sigma"],
        "Detection": [
            """def rule(event):
    if all(
        [
            event.deep_get("EventID", default="") == 4688,
            event.deep_get("ExtraEventData", "NewValue", default="") == "banana",
            event.deep_get("ExtraEventData", "CommandLine", default="") == "cmdline_test",
            event.deep_get("ExtraEventData", "NewProcessName", default="") == "test_image",
        ]
    ):
        return True
    return False
"""
        ],
    }

    assert backend.convert(rule_collection=rule, output_format="python") == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_windows_logsource_basic_sdyaml(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "windows_logsource_panther"}
    )
    resolver = ProcessingPipelineResolver(
        {"windows_logsource_panther": windows_logsource_panther_pipeline()}
    )
    pipeline = resolver.resolve_pipeline("windows_logsource_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            category: ps_script
            product: windows
        detection:
            sel:
                Details: "banana"
                CommandLine: "cmdline_test"
                Image: "test_image"
            condition: sel
    """
    )

    expected = yaml.dump(
        {
            "Description": "description",
            "AnalysisType": "rule",
            "DisplayName": "Test Title",
            "Enabled": True,
            "LogTypes": ["Windows.EventLogs"],
            "Tags": ["Sigma"],
            "Detection": [
                {
                    "All": [
                        {
                            "Condition": "IsIn",
                            "KeyPath": "Channel",
                            "Values": [
                                "Microsoft-Windows-PowerShell/Operational",
                                "PowerShellCore/Operational",
                            ],
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "EventID",
                            "Value": 4104,
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "ExtraEventData.Details",
                            "Value": "banana",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "ExtraEventData.CommandLine",
                            "Value": "cmdline_test",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "ExtraEventData.Image",
                            "Value": "test_image",
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule, output_format="sdyaml") == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_windows_logsource_basic_python(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "windows_logsource_panther"}
    )
    resolver = ProcessingPipelineResolver(
        {"windows_logsource_panther": windows_logsource_panther_pipeline()}
    )
    pipeline = resolver.resolve_pipeline("windows_logsource_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
            title: Test Title
            id: {rule_id}
            description: description
            logsource:
                category: ps_script
                product: windows
            detection:
                sel:
                    Details: "banana"
                    CommandLine: "cmdline_test"
                    Image: "test_image"
                condition: sel
        """
    )

    expected = {
        "Description": "description",
        "AnalysisType": "rule",
        "DisplayName": "Test Title",
        "Enabled": True,
        "LogTypes": ["Windows.EventLogs"],
        "Tags": ["Sigma"],
        "Detection": [
            """def rule(event):
    if all(
        [
            event.deep_get("Channel", default="")
            in ["Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational"],
            event.deep_get("EventID", default="") == 4104,
            event.deep_get("ExtraEventData", "Details", default="") == "banana",
            event.deep_get("ExtraEventData", "CommandLine", default="") == "cmdline_test",
            event.deep_get("ExtraEventData", "Image", default="") == "test_image",
        ]
    ):
        return True
    return False
"""
        ],
    }

    assert backend.convert(rule_collection=rule, output_format="python") == expected
