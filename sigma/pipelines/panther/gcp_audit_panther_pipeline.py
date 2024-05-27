from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
    FieldPrefixMappingTransformation,
)

from sigma.pipelines.panther.processing import DetectionContainsFieldName
from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


def gcp_audit_panther_pipeline():
    return ProcessingPipeline(
        name="GCP Audit Panther Pipeline",
        items=[
            ProcessingItem(
                transformation=FieldMappingTransformation(
                    {
                        "gcp.audit.method_name": "protoPayload.methodName",
                    }
                ),
                detection_item_conditions=[DetectionContainsFieldName()],
            ),
            ProcessingItem(
                transformation=FieldPrefixMappingTransformation(
                    {
                        "data.protoPayload": "protoPayload",
                    }
                ),
                detection_item_conditions=[DetectionContainsFieldName()],
            ),
        ],
        postprocessing_items=[QueryPostprocessingItem(transformation=SdYamlTransformation())],
    )
