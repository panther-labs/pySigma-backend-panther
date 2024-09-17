from os import path
from typing import Any

import click
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaLevel, SigmaRule

SEVERITY_MAPPING = {
    SigmaLevel.INFORMATIONAL: "Info",
    SigmaLevel.LOW: "Low",
    SigmaLevel.MEDIUM: "Medium",
    SigmaLevel.HIGH: "High",
    SigmaLevel.CRITICAL: "Critical",
}


class SdYamlTransformation(QueryPostprocessingTransformation):
    identifier = "SDYaml"

    _logsources_map: dict[tuple[str, str], str] = {
        ("okta", "okta"): "Okta.SystemLog",
        ("aws", "cloudtrail"): "AWS.CloudTrail",
        ("github", "audit"): "GitHub.Audit",
        ("gcp", "gcp.audit"): "GCP.AuditLog",
    }

    def apply(self, pipeline: ProcessingPipeline, rule: SigmaRule, query: Any) -> Any:
        res = {
            "AnalysisType": "rule",
            "DisplayName": rule.title,
            "Description": rule.description,
            "Tags": ["Sigma"] + [tag.name for tag in rule.tags],
            "Enabled": True,
            "Detection": [query],
        }

        if rule.references:
            res["Reference"] = rule.references[0]

        if rule.status:
            res["Description"] += f"\n\nStatus: {rule.status}"

        if rule.author:
            res["Description"] += f"\n\nAuthor: {rule.author}"

        if rule.falsepositives:
            description = res["Description"] or ""
            if description:
                description += "\n"
            res["Description"] = description + "False Positives: " + ", ".join(rule.falsepositives)

        if rule.source:
            res["RuleID"] = path.split(rule.source.path)[-1].replace(".yml", "")

            # DO NOT FORGET TO REMOVE THIS KEY FROM OUTPUT
            # used to pass file name to output
            res["SigmaFile"] = path.split(rule.source.path)[-1]

        if rule.level:
            res["Severity"] = SEVERITY_MAPPING[rule.level]

        log_types = self._detect_log_types(rule)
        if len(log_types) == 0:
            raise SigmaFeatureNotSupportedByBackendError("Can't map any LogTypes")
        else:
            res["LogTypes"] = log_types

        if rule.tags:
            mittre_tags = []
            for tag in rule.tags:
                if tag.namespace == "attack" and tag.name.startswith("t"):
                    mittre_tags.append(tag.name.upper())
            res["Reports"] = {"MITRE ATT&CK": mittre_tags}

        return res

    def _detect_log_types(self, rule: SigmaRule) -> [str]:
        log_types = []

        mapped_log_type = self._logsources_map.get((rule.logsource.product, rule.logsource.service))
        if mapped_log_type:
            log_types.append(mapped_log_type)

        cli_context = click.get_current_context(silent=True)
        if cli_context:
            if "crowdstrike_panther" in cli_context.params["pipeline"]:
                log_types.append("Crowdstrike.FDREvent")

            if "carbon_black_panther" in cli_context.params["pipeline"]:
                log_types.append("CarbonBlack.EndpointEvent")

            if "sentinelone_panther" in cli_context.params["pipeline"]:
                log_types.append("SentinelOne.DeepVisibilityV2")

            if any(
                [
                    "windows_audit_panther" in cli_context.params["pipeline"],
                    "windows_logsource_panther" in cli_context.params["pipeline"],
                ]
            ):
                log_types.append("Windows.EventLogs")
        return log_types
