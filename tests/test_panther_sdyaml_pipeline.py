import uuid

import yaml
from sigma.collection import SigmaCollection


def test_basic(sigma_sdyaml_backend):
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {uuid.uuid4()}
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Field1: "banana"
            condition: sel
    """
    )

    expected = yaml.dump(
        {
            "AnalysisType": "rule",
            "DisplayName": "Test Title",
            "Description": None,
            "Tags": [],
            "Enabled": True,
            "Detection": [
                {
                    "All": [
                        {
                            "Condition": "Equals",
                            "KeyPath": "event_simpleName",
                            "Value": "ProcessRollup2",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "Field1",
                            "Value": "banana",
                        },
                    ]
                },
            ],
        }
    )

    assert sigma_sdyaml_backend.convert(rule) == expected
