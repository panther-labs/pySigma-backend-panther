from typing import Union

from sigma.processing.conditions import (
    DetectionItemProcessingCondition,
    RuleContainsDetectionItemCondition,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem


class RuleIContainsDetectionItemCondition(RuleContainsDetectionItemCondition):
    # same as RuleContainsDetectionItemCondition, but case-insensitive
    def find_detection_item(self, detection: Union[SigmaDetectionItem, SigmaDetection]) -> bool:
        if isinstance(detection, SigmaDetection):
            for detection_item in detection.detection_items:
                if self.find_detection_item(detection_item):
                    return True
        elif isinstance(detection, SigmaDetectionItem):
            if (
                detection.field is not None
                and detection.field == self.field
                and str(self.sigma_value).lower() in [str(v).lower() for v in detection.value]
            ):
                return True
        else:
            raise TypeError("Parameter of type SigmaDetection or SigmaDetectionItem expected.")

        return False


class DetectionContainsFieldName(DetectionItemProcessingCondition):
    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        if detection_item.field is not None:
            return True
        return False
