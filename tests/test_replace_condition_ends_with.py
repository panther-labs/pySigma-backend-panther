import uuid

import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from sigma.pipelines.panther.replace_condition_ends_with import ReplaceConditionEndsWith


class TestReplaceConditionEndsWith:
    def test_with_one_value(self, pipeline, sigma_sdyaml_backend):
        raw_rule = f"""
        title: Test Title
        id: {uuid.uuid4()}
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Field: "banana"
            condition: sel
        """

        expected = f"""
        AnalysisType: rule
        Description: null
        Detection:
        - All:
          - Condition: Equals
            KeyPath: event_simpleName
            Value: ProcessRollup2
          - Condition: EndsWith
            KeyPath: UpdatedField
            Value: banana
        DisplayName: Test Title
        Enabled: true
        Tags: []
        """
        transformation = ReplaceConditionEndsWith(
            source_field_name="Field", target_field_name="UpdatedField"
        )
        rule = SigmaRule.from_yaml(raw_rule)
        transformation.apply(pipeline, rule)

        res = sigma_sdyaml_backend.convert(SigmaCollection(rules=[rule]))
        assert yaml.safe_load(res) == yaml.safe_load(expected)

    def test_with_multiple_values(self, pipeline, sigma_sdyaml_backend):
        raw_rule = f"""
        title: Test Title
        id: {uuid.uuid4()}
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Field:
                  - "banana"
                  - "apple"
            condition: sel
        """

        expected = f"""
        AnalysisType: rule
        Description: null
        Detection:
        - All:
          - Condition: Equals
            KeyPath: event_simpleName
            Value: ProcessRollup2
          - Any:
              - Condition: EndsWith
                KeyPath: UpdatedField
                Value: banana
              - Condition: EndsWith
                KeyPath: UpdatedField
                Value: apple
        DisplayName: Test Title
        Enabled: true
        Tags: []
        """
        transformation = ReplaceConditionEndsWith(
            source_field_name="Field", target_field_name="UpdatedField"
        )
        rule = SigmaRule.from_yaml(raw_rule)
        transformation.apply(pipeline, rule)

        res = sigma_sdyaml_backend.convert(SigmaCollection(rules=[rule]))
        assert yaml.safe_load(res) == yaml.safe_load(expected)

    def test_with_nested_detections(self, pipeline, sigma_sdyaml_backend):
        raw_rule = f"""
        title: Test Title
        id: {uuid.uuid4()}
        logsource:
            category: process_creation
            product: windows
        detection:
            selection_img:
                - Image|endswith: '\WMIC.exe'
                - OriginalFileName: 'wmic.exe'
            selection_cli:
                CommandLine|contains: '/node:'
            filter_localhost:
                CommandLine|contains:
                    - '/node:127.0.0.1 '
                    - '/node:localhost '
            condition: all of selection_* and not 1 of filter_*
        """

        expected = f"""
        AnalysisType: rule
        Description: null
        Detection:
          - All:
            - Condition: Equals
              KeyPath: event_simpleName
              Value: ProcessRollup2
            - All:
              - Condition: EndsWith
                KeyPath: ReplacedFileName
                Value: wmic.exe
              - All:
                - All:
                  - Any:
                    - Condition: EndsWith
                      KeyPath: image
                      Value: \\WMIC.exe
                  - Condition: Contains
                    KeyPath: command_line
                    Value: '/node:'
                - All:
                  - Condition: DoesNotContain
                    KeyPath: command_line
                    Value: '/node:127.0.0.1 '    
                  - Condition: DoesNotContain
                    KeyPath: command_line
                    Value: '/node:localhost '   
        DisplayName: Test Title
        Enabled: true
        Tags: []
        """
        transformation = ReplaceConditionEndsWith(
            source_field_name="OriginalFileName", target_field_name="ReplacedFileName"
        )
        rule = SigmaRule.from_yaml(raw_rule)
        transformation.apply(pipeline, rule)

        res = sigma_sdyaml_backend.convert(SigmaCollection(rules=[rule]))
        assert yaml.safe_load(res) == yaml.safe_load(expected)
