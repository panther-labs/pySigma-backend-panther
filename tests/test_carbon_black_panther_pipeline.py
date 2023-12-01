import uuid

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherSdyamlBackend
from sigma.pipelines.panther import carbon_black_panther_pipeline


def test_basic():
    resolver = ProcessingPipelineResolver({"carbon_black_panther": carbon_black_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("carbon_black_panther")
    backend = PantherSdyamlBackend(pipeline)

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
                            "All": [
                                {
                                    "Condition": "Equals",
                                    "KeyPath": "type",
                                    "Value": "endpoint.event.procstart",
                                },
                                {
                                    "All": [
                                        {
                                            "Condition": "Equals",
                                            "KeyPath": "device_os",
                                            "Value": "MAC",
                                        },
                                        {
                                            "All": [
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
                                        },
                                    ]
                                },
                            ]
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule) == expected
