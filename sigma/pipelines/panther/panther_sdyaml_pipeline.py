from dataclasses import dataclass
from typing import Optional, List
from sigma.processing.conditions import FieldNameProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    ReplaceStringTransformation,
    FieldMappingTransformationBase,
)
from sigma.rule import SigmaDetectionItem


@dataclass
class AddFieldnamePrefixAndSuffixTransformation(FieldMappingTransformationBase):
    """
    Add field name prefix.
    """

    prefix: str
    suffix: str

    # todo-jje: what is this?
    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        if type(orig_field := detection_item.field) is str:
            detection_item.field = self.prefix + detection_item.field + self.suffix
            self.pipeline.field_mappings.add_mapping(orig_field, detection_item.field)
        self.processing_item_applied(detection_item)

    def apply_field_name(self, field: str) -> List[str]:
        return [self.prefix + field + self.suffix]


panther_transformation = AddFieldnamePrefixAndSuffixTransformation.from_dict({
    "prefix": 'event.get("',
    "suffix": '")',
})

no_transformation = AddFieldnamePrefixAndSuffixTransformation.from_dict({
    "prefix": "",
    "suffix": "",
})


@dataclass
class AlwaysMatchFieldCondition(FieldNameProcessingCondition):
    """
    Always matches on field name if exists
    """

    # todo-jje: what is pipeline for?
    def match_field_name(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        field: Optional[str],
    ) -> bool:
        if field is None:
            return False
        else:
            return True


# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.


def panther_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to Panther Transformation",
        # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline.
        #   This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        # allowed_backends=frozenset(),
        # The priority defines the order pipelines are applied. See documentation for common values.
        # priority=20,
        items=[
            ProcessingItem(
                identifier="panther_event_get",
                # transformation=ReplaceStringTransformation(
                #     regex="^(.*)$",
                #     replacement="event.get('\\1')",
                # ),
                transformation=panther_transformation,
                # transformation=no_transformation,
                field_name_conditions=[
                    AlwaysMatchFieldCondition(),
                ],
            )
        ],
    )
