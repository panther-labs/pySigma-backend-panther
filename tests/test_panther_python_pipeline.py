import pytest
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.backends.test import TextQueryTestBackend

from sigma.backends.panther_python import PantherPythonBackend
# from sigma.pipelines.panther_python.panther_pipeline import panther_pipeline


# @pytest.fixture
# def resolver():
#     return ProcessingPipelineResolver({
#         "panther": panther_pipeline,
#     })
#
# @pytest.fixture
# def sigma_rule_basic():
#     return SigmaCollection.from_yaml("""
#         title: Test Title
#         logsource:
#             category: anything
#             product: whatever
#         detection:
#             sel:
#                 Field1: "banana"
#             condition: sel
#     """)
#
# def test_basic(resolver : ProcessingPipelineResolver, sigma_rule_basic):
#     pipeline = resolver.resolve_pipeline("panther")
#     backend = TextQueryTestBackend(pipeline)
#     # backend = PantherPythonBackend(pipeline)
#     assert backend.convert(sigma_rule_basic) == ['event.get("Field1")="banana"']

