import uuid

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther import gcp_audit_panther_pipeline


def test_basic():
    resolver = ProcessingPipelineResolver({"gcp_audit_panther": gcp_audit_panther_pipeline()})
    pipeline = resolver.resolve_pipeline("gcp_audit_panther")
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

    assert backend.convert(rule) == expected
