import uuid
from unittest import mock

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import panther_pipeline


def test_basic_sdyaml():
    resolver = ProcessingPipelineResolver({"panther": panther_pipeline()})
    pipeline = resolver.resolve_pipeline("panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            product: gcp
            service: gcp.audit
        detection:
            sel:
                Field1: "banana"
                data.protoPayload.cat: "dog"
                gcp.audit.method_name: "eat"
            condition: sel
    """
    )

    expected = yaml.dump(
        {
            "Description": "description",
            "AnalysisType": "rule",
            "DisplayName": "Test Title",
            "Enabled": True,
            "LogTypes": ["GCP.AuditLog"],
            "Tags": ["Sigma"],
            "Detection": [
                {
                    "All": [
                        {
                            "Condition": "Equals",
                            "KeyPath": "Field1",
                            "Value": "banana",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "protoPayload.cat",
                            "Value": "dog",
                        },
                        {
                            "Condition": "Equals",
                            "KeyPath": "protoPayload.methodName",
                            "Value": "eat",
                        },
                    ]
                }
            ],
        }
    )

    assert backend.convert(rule, output_format="sdyaml") == expected


@mock.patch("sigma.pipelines.panther.sdyaml_transformation.click")
def test_with_keywords_python(mock_click):
    mock_click.get_current_context.return_value = mock.MagicMock(
        params={"pipeline": "gcp_audit_panther"}
    )
    resolver = ProcessingPipelineResolver({"panther": panther_pipeline()})
    pipeline = resolver.resolve_pipeline("panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            product: gcp
            service: gcp.audit
        detection:
            sel:
                Field1: "banana"
                data.protoPayload.cat: "dog"
                gcp.audit.method_name: "eat"
            keywords:
                - "word1"
                - "word2"
            condition: sel and keywords
    """
    )

    expected = {
        "AnalysisType": "rule",
        "Description": "description",
        "Detection": [
            """import json


def rule(event):
    if all(
        [
            event.deep_get("Field1", default="") == "banana",
            event.deep_get("protoPayload", "cat", default="") == "dog",
            event.deep_get("protoPayload", "methodName", default="") == "eat",
            any(["word1" in json.dumps(event.to_dict()), "word2" in json.dumps(event.to_dict())]),
        ]
    ):
        return True
    return False
"""
        ],
        "DisplayName": "Test Title",
        "Enabled": True,
        "LogTypes": ["GCP.AuditLog"],
        "Tags": ["Sigma"],
    }

    assert backend.convert(rule, output_format="python") == expected


def test_with_keywords_sdyaml():
    resolver = ProcessingPipelineResolver({"panther": panther_pipeline()})
    pipeline = resolver.resolve_pipeline("panther")
    backend = PantherBackend(pipeline)

    rule_id = uuid.uuid4()
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test Title
        id: {rule_id}
        description: description
        logsource:
            category: gcp
            product: gcp.audit
        detection:
            sel:
                Field1: "banana"
                data.protoPayload.cat: "dog"
                gcp.audit.method_name: "eat"
            keywords:
                - "word1"
                - "word2"
            condition: sel and keywords
    """
    )

    with pytest.raises(SigmaFeatureNotSupportedByBackendError) as err:
        assert backend.convert(rule, output_format="sdyaml")
    assert (
        err.value.args[0]
        == 'Search without specifying a Key is not supported. First such key is "word1".'
    )
