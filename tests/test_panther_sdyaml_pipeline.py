import pytest
import yaml

from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.backends.panther import PantherSdyamlBackend
from sigma.pipelines.panther.panther_sdyaml_pipeline import panther_sdyaml_pipeline


@pytest.fixture
def sigma_sdyaml_backend():
    resolver = ProcessingPipelineResolver({"panther_sdyaml": panther_sdyaml_pipeline})
    pipeline = resolver.resolve_pipeline("panther_sdyaml")
    backend = PantherSdyamlBackend(pipeline)
    return backend


def test_basic(sigma_sdyaml_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Title
        logsource:
            category: anything
            product: whatever
        detection:
            sel:
                Field1: "banana"
            condition: sel
    """)

    expected = yaml.dump([{
        "Condition": "Equals",
        "Key": "Field1",
        "Value": "banana",
    }])

    assert sigma_sdyaml_backend.convert(rule) == expected
