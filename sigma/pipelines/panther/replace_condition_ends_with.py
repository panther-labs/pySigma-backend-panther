import logging
from dataclasses import dataclass, field
from typing import Optional

from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule


def _get_nested_fields_mapping(di):
    fields_mapping = {}
    if isinstance(di, SigmaDetection):
        for nested_di in di.detection_items:
            fields_mapping.update(_get_nested_fields_mapping(nested_di))

    elif isinstance(di, SigmaDetectionItem):
        fields_mapping[di.field] = di
    else:
        logging.warning("Unknown detection item type: %s", type(di))
    return fields_mapping


def _remove_field(di, field_name):
    if isinstance(di, SigmaDetection):
        for nested_di in di.detection_items:
            if isinstance(nested_di, SigmaDetection):
                _remove_field(nested_di, field_name)
                continue

            if field_name == nested_di.field:
                di.detection_items.remove(nested_di)


@dataclass
class ReplaceConditionEndsWith(AddConditionTransformation):
    source_field_name: Optional[str] = field(default=None)
    target_field_name: Optional[str] = field(default=None)

    def apply(self, pipeline: ProcessingPipeline, rule: SigmaRule):
        fields_mapping = {}
        if not rule.detection:
            return

        for item in rule.detection.detections.values():
            fields_mapping = {**fields_mapping, **_get_nested_fields_mapping(item)}
            _remove_field(item, self.source_field_name)

        if self.source_field_name in fields_mapping:
            field = fields_mapping[self.source_field_name]
            self.conditions = [
                {
                    f"{self.target_field_name}|endswith": str(value),
                }
                for value in field.value
            ]

        if not self.conditions:
            return
        super().apply(pipeline, rule)
