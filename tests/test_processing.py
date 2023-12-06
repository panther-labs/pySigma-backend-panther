from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString

from sigma.pipelines.panther.processing import RuleIContainsDetectionItemCondition


class TestRuleIContainsDetectionItemCondition:
    def test_find_detection_item_match(self):
        detection_item = SigmaDetectionItem(
            field="Protocol", value=[SigmaString("TCP")], modifiers=[]
        )

        condition = RuleIContainsDetectionItemCondition(field="Protocol", value="tcp")
        assert condition.find_detection_item(detection_item)

    def test_find_detection_item_dont_match(self):
        detection_item = SigmaDetectionItem(
            field="Protocol", value=[SigmaString("TCP")], modifiers=[]
        )

        condition = RuleIContainsDetectionItemCondition(field="Protocol", value="udp")
        assert not condition.find_detection_item(detection_item)

    def test_find_detection_item_with_sigma_detection(self):
        detection_item = SigmaDetectionItem(
            field="Protocol", value=[SigmaString("TCP")], modifiers=[]
        )
        detection = SigmaDetection(detection_items=[detection_item])

        condition = RuleIContainsDetectionItemCondition(field="Protocol", value="tcp")
        assert condition.find_detection_item(detection)
