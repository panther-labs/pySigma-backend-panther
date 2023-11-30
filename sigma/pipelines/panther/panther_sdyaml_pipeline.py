from dataclasses import dataclass, field
from typing import Optional

import click
from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.conditions import LogsourceCondition, RuleProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation, AddConditionTransformation
from sigma.rule import SigmaRule

from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


def logsource_windows():
    return LogsourceCondition(product="windows")


def logsource_mac():
    return LogsourceCondition(product="mac")


def logsource_linux():
    return LogsourceCondition(product="linux")


def logsource_file_event():
    return LogsourceCondition(category="file_event")


def logsource_network_connection():
    return LogsourceCondition(category="network_connection")


def logsource_process_creation():
    return LogsourceCondition(category="process_creation")


@dataclass
class PipelineWasUsed(RuleProcessingCondition):
    pipeline: Optional[str] = field(default=None)

    def match(self, pipeline: ProcessingPipeline, rule: SigmaRule) -> bool:
        cli_context = click.get_current_context(silent=True)
        return cli_context and self.pipeline in cli_context.params["pipeline"]


def crowdstrike_pipeline_was_used():
    return PipelineWasUsed("crowdstrike_fdr")


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
            ProcessingItem(
                transformation=AddConditionTransformation({
                    "event_simpleName": "ProcessRollup2",
                }), rule_conditions=[
                    logsource_windows(),
                ]
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({
                    "event_platform": "Windows",
                }), rule_conditions=[
                    logsource_windows(),
                ]
            ),
            ProcessingItem(transformation=AddConditionTransformation({
                "event_platform": "Mac",
            }), rule_conditions=[logsource_mac()]),
            ProcessingItem(transformation=AddConditionTransformation({
                "event_platform": "Linux",
            }), rule_conditions=[logsource_linux()]),
            ProcessingItem(
                transformation=AddConditionTransformation({
                    "event_simpleName": "FileOpenInfo",
                }), rule_conditions=[logsource_file_event()]
            ),
            ProcessingItem(
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "NetworkConnectIP4", "NetworkConnectIP6", "NetworkReceiveAcceptIP4", "NetworkReceiveAcceptIP6"
                        ],
                    }
                ),
                rule_conditions=[logsource_network_connection()]
            ),
            ProcessingItem(
                transformation=FieldMappingTransformation(
                    {
                        "sha256": "event.SHA256HashData",
                        "sha1": "event.SHA1HashData",
                        "ParentImage": "event.ParentBaseFileName",
                        "Image": "event.ImageFileName",
                        "CommandLine": "event.CommandLine",
                        "md5": "event.MD5HashData",
                    }
                ),
                rule_conditions=[
                    crowdstrike_pipeline_was_used(),
                ],
            ),
        ],
        postprocessing_items=[
            SdYamlTransformation(),
        ]
    )
