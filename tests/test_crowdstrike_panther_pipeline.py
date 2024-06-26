import uuid
from unittest import mock

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import crowdstrike_panther_pipeline


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_basic(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "crowdstrike_panther"}
    )
    resolver = ProcessingPipelineResolver({"crowdstrike_panther": crowdstrike_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("crowdstrike_panther")
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
                Field1: "banana"
                DestinationIp: 127.0.0.1
                Initiated: "true"
                ParentImage: C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe
            condition: sel
    """
    )

    expected = yaml.dump(
        {
            "Description": "description",
            "AnalysisType": "rule",
            "DisplayName": "Test Title",
            "Enabled": True,
            "LogTypes": ["Crowdstrike.FDREvent"],
            "Tags": ["Sigma"],
            "Detection": [
                {
                    "All": [
                        {
                            "Condition": "Equals",
                            "KeyPath": "event_platform",
                            "Value": "Windows",
                        },
                        {
                            "Condition": "IsIn",
                            "KeyPath": "event_simpleName",
                            "Values": ["ProcessRollup2", "SyntheticProcessRollup2"],
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Field1",
                            "Value": "banana",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "DestinationIp",
                            "Value": "127.0.0.1",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Initiated",
                            "Value": "true",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "ParentBaseFileName",
                            "Value": "MonitoringHost.exe",
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule) == expected
