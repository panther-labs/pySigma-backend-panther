import pytest
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaDetection, SigmaLogSource, SigmaDetectionItem, SigmaRule
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.backends.panther import PantherSdyamlBackend
from sigma.pipelines.panther.panther_sdyaml_pipeline import panther_sdyaml_pipeline


@pytest.fixture
def sigma_sdyaml_backend():
    resolver = ProcessingPipelineResolver({"panther_sdyaml": panther_sdyaml_pipeline})
    pipeline = resolver.resolve_pipeline("panther_sdyaml")
    backend = PantherSdyamlBackend(pipeline)
    return backend


@pytest.fixture
def pipeline():
    return ProcessingPipeline([], [])


@pytest.fixture
def sigma_detection():
    return SigmaDetection(detection_items=[SigmaDetectionItem("query", [], value=None)])


@pytest.fixture
def log_source():
    return SigmaLogSource(product="windows")


@pytest.fixture
def rule(sigma_detection):
    return SigmaRule("rule title", SigmaLogSource(product="windows"), sigma_detection)
