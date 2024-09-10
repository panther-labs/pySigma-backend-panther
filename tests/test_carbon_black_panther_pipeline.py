import uuid
from unittest import mock

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import carbon_black_panther_pipeline


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_basic(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "carbon_black_panther"}
    )
    resolver = ProcessingPipelineResolver({"carbon_black_panther": carbon_black_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("carbon_black_panther")
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
                DestinationIp: 127.0.0.1
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
            "LogTypes": ["CarbonBlack.EndpointEvent"],
            "Tags": ["Sigma"],
            "Detection": [
                {
                    "All": [
                        {
                            "Condition": "Equals",
                            "KeyPath": "netconn_inbound",
                            "Value": "false",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "type",
                            "Value": "endpoint.event.procstart",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "device_os",
                            "Value": "MAC",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Field1",
                            "Value": "banana",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "remote_ip",
                            "Value": "127.0.0.1",
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule, output_format="sdyaml") == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_not_supported_rule_type(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "carbon_black_panther"}
    )
    resolver = ProcessingPipelineResolver({"carbon_black_panther": carbon_black_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("carbon_black_panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            category: registry_add
            product: macos
        detection:
            sel:
                Field1: "banana"
                DestinationIp: 127.0.0.1
                Initiated: "true"
            condition: sel
    """
    )

    with pytest.raises(SigmaTransformationError) as err:
        backend.convert(rule)
    assert (
        err.value.args[0] == "Rule type not currently supported by the CarbonBlack Sigma pipeline"
    )
