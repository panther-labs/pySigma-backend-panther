import logging
import uuid
from os import path
from typing import Any
from sigma.processing.pipeline import ProcessingPipeline
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

        if rule.references:
            res["Reference"] = ", ".join(rule.references)

        if rule.author:
            res["Description"] += f"\n\nAuthor: {rule.author}"

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
