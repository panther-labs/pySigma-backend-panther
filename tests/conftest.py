import pytest
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.rule import (
    SigmaDetection,
    SigmaDetectionItem,
    SigmaDetections,
    SigmaLogSource,
    SigmaRule,
)
from sigma.types import SigmaNull

from sigma.backends.panther import PantherBackend
from sigma.pipelines.panther.panther_pipeline import panther_pipeline


@pytest.fixture
def sigma_backend():
    resolver = ProcessingPipelineResolver({"panther": panther_pipeline})
    pipeline = resolver.resolve_pipeline("panther")
    backend = PantherBackend(pipeline)
    return backend


@pytest.fixture
def pipeline():
    return ProcessingPipeline([], [])


@pytest.fixture
def sigma_detection():
    return SigmaDetection(detection_items=[SigmaDetectionItem("query", [], value=[SigmaNull()])])


@pytest.fixture
def log_source():
    return SigmaLogSource(product="windows")


@pytest.fixture
def rule(sigma_detection):
    return SigmaRule(
        "rule title",
        logsource=SigmaLogSource(product="okta", service="okta"),
        detection=SigmaDetections({"query": sigma_detection}, condition=["query"]),
    )
