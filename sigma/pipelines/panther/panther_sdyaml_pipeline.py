import logging
import uuid
from os import path
from typing import Any
from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule

LOG_TYPES_MAPPING = {
    "windows": "Windows.EventLogs",
}


class SdYamlTransformation(QueryPostprocessingTransformation):
    identifier = "SDYaml"

    def apply(self, pipeline: ProcessingPipeline, rule: SigmaRule, query: Any) -> Any:
        res = {
            "AnalysisType": "rule",
            "DisplayName": rule.title,
            "Description": rule.description,
            "Tags": [tag.name for tag in rule.tags],
            "Enabled": True,
            "Detection": [query],
        }
        rule_id = rule.id or uuid.uuid4()
        res["RuleID"] = str(rule_id)

        if rule.source:
            res["SigmaFile"] = path.split(rule.source.path)[-1]

        if rule.level:
            res["Severity"] = rule.level.name

        key = rule.logsource.product
        log_type = LOG_TYPES_MAPPING.get(rule.logsource.product)
        if log_type is None:
            logging.error(f"Can't find LogTypes mapping for {key}")
        else:
            res["LogTypes"] = [log_type]

        return res, True


def panther_sdyaml_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to Panther Transformation",
        # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline.
        #   This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        # allowed_backends=frozenset(),
        # The priority defines the order pipelines are applied. See documentation for common values.
        # priority=20,
        items=[
            ProcessingItem(
                transformation=FieldMappingTransformation(
                    {
                        "CommandLine": "command_line",
                        "Image": "image",
                        "ParentCommandLine": "parent_command_line",
                        "ParentImage": "parent_image",
                    }
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ],
            ),
        ],
        postprocessing_items=[
            SdYamlTransformation(),
        ]
    )
