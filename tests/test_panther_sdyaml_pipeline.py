import uuid

import yaml
from sigma.collection import SigmaCollection


def test_basic(sigma_backend):
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {uuid.uuid4()}
        logsource:
            service: okta
            product: okta
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
            "Tags": ["Sigma"],
            "Enabled": True,
            "LogTypes": ["Okta.SystemLog"],
            "Detection": [
                {
                    "Condition": "Equals",
                    "KeyPath": "Field1",
                    "Value": "banana",
                },
            ],
        }
    )

    assert sigma_backend.convert(rule) == expected
