import logging
import uuid
from os import path
from typing import Any
import click
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule


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

        log_types = self._detect_log_types(rule)
        if len(log_types) == 0:
            logging.error(f"Can't find any LogTypes")
        else:
            res["LogTypes"] = log_types

        return res, True

    def _detect_log_types(self, rule: SigmaRule) -> [str]:
        log_types = []
        if rule.logsource.product == "okta" and rule.logsource.service == "okta":
            log_types.append("Okta.SystemLog")

        if rule.logsource.product == "aws" and rule.logsource.service == "cloudtrail":
            log_types.append("AWS.CloudTrail")

        cli_context = click.get_current_context(silent=True)
        if cli_context:
            if "crowdstrike_fdr" in cli_context.params["pipeline"]:
                log_types.append("Crowdstrike.FDREvent")

            if "carbon_black_panther" in cli_context.params["pipeline"]:
                log_types.append("CarbonBlack.EndpointEvent")
        return log_types
