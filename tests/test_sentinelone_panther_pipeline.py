import uuid
from unittest import mock

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import sentinelone_panther_pipeline


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_basic_sdyaml(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "sentinelone_panther"}
    )
    resolver = ProcessingPipelineResolver({"sentinelone_panther": sentinelone_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("sentinelone_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            category: process_creation
            product: macos
        detection:
            sel:
                Field1: "banana"
                CommandLine: "cmdline_test"
                Initiated: "true"
            condition: sel
    """
    )

    expected = yaml.dump(
        {
            "Description": "description",
            "AnalysisType": "rule",
            "DisplayName": "Test Title",
            "Enabled": True,
            "LogTypes": ["SentinelOne.DeepVisibilityV2"],
            "Tags": ["Sigma"],
            "Detection": [
                {
                    "All": [
                        {
                            "Condition": "Equals",
                            "KeyPath": "EventType",
                            "Value": "Process Creation",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "EndpointOS",
                            "Value": "osx",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Field1",
                            "Value": "banana",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "TgtProcCmdLine",
                            "Value": "cmdline_test",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Initiated",
                            "Value": "true",
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule) == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_basic_python(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={
            "pipeline": "sentinelone_panther",
        }
    )
    resolver = ProcessingPipelineResolver({"sentinelone_panther": sentinelone_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("sentinelone_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            category: process_creation
            product: macos
        detection:
            sel:
                Field1: "banana"
                CommandLine: "cmdline_test"
                Initiated: "true"
            condition: sel
    """
    )

    expected = {
        "Description": "description",
        "AnalysisType": "rule",
        "DisplayName": "Test Title",
        "Enabled": True,
        "LogTypes": ["SentinelOne.DeepVisibilityV2"],
        "Tags": ["Sigma"],
        "Detection": [
            """def rule(event):
    if all(
        [
            event.deep_get("EventType", default="") == "Process Creation",
            event.deep_get("EndpointOS", default="") == "osx",
            event.deep_get("Field1", default="") == "banana",
            event.deep_get("TgtProcCmdLine", default="") == "cmdline_test",
            event.deep_get("Initiated", default="") == "true",
        ]
    ):
        return True
    return False
"""
        ],
    }

    assert backend.convert(rule_collection=rule, output_format="python") == expected
