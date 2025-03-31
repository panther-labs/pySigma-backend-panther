import uuid
from unittest import mock

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import sysmon_panther_pipeline


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_sysmon_basic_sdyaml(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "sysmon_panther"}
    )
    resolver = ProcessingPipelineResolver({"sysmon_panther": sysmon_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("sysmon_panther")
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
                            "KeyPath": "Channel",
                            "Value": "Microsoft-Windows-Sysmon/Operational",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "EventID",
                            "Value": 1,
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Details",
                            "Value": "banana",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "CommandLine",
                            "Value": "cmdline_test",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Image",
                            "Value": "test_image",
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule, output_format="sdyaml") == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_sysmon_basic_python(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "sysmon_panther"}
    )
    resolver = ProcessingPipelineResolver({"sysmon_panther": sysmon_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("sysmon_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
            title: Test Title
            id: {rule_id}
            description: description
            logsource:
                category: registry_event
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
            event.deep_get("Channel", default="") == "Microsoft-Windows-Sysmon/Operational",
            event.deep_get("EventID", default="") in [12, 13, 14],
            event.deep_get("Details", default="") == "banana",
            event.deep_get("CommandLine", default="") == "cmdline_test",
            event.deep_get("Image", default="") == "test_image",
        ]
    ):
        return True
    return False
"""
        ],
    }

    assert backend.convert(rule_collection=rule, output_format="python") == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_sysmon_basic_pantherflow(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "sysmon_panther"}
    )
    resolver = ProcessingPipelineResolver({"sysmon_panther": sysmon_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("sysmon_panther")
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

    expected = """ | where p_event_time > time.ago(1d)
 | where Channel == 'Microsoft-Windows-Sysmon/Operational'
    and EventID == 1
    and Details == 'banana'
    and CommandLine == 'cmdline_test'
    and Image == 'test_image'
"""

    result = backend.convert(rule_collection=rule, output_format="pantherflow")
    assert result["Detection"][0] == expected
