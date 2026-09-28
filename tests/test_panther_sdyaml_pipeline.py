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

    assert sigma_backend.convert(rule, output_format="sdyaml") == expected


def test_status_and_author_without_description(sigma_backend):
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {uuid.uuid4()}
        status: test
        author: Someone
        logsource:
            service: okta
            product: okta
        detection:
            sel:
                Field1: "banana"
            condition: sel
    """
    )

    converted = yaml.safe_load(sigma_backend.convert(rule, output_format="sdyaml"))
    assert converted["Description"] == "\n\nStatus: test\n\nAuthor: Someone"
