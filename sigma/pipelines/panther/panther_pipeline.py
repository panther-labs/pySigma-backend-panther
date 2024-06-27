from dataclasses import dataclass, field
from typing import Optional

import click
from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.conditions import (
    IncludeFieldCondition,
    LogsourceCondition,
    RuleProcessingCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    FieldPrefixMappingTransformation,
)
from sigma.rule import SigmaRule

from sigma.pipelines.panther.processing import DetectionContainsFieldName
from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


def logsource_windows():
    return LogsourceCondition(product="windows")


def logsource_mac():
    return LogsourceCondition(product="macos")


def logsource_linux():
    return LogsourceCondition(product="linux")


def logsource_file_event():
    return LogsourceCondition(category="file_event")


def logsource_network_connection():
    return LogsourceCondition(category="network_connection")


def logsource_process_creation():
    return LogsourceCondition(category="process_creation")


def logsource_gcp_audit() -> LogsourceCondition:
    return LogsourceCondition(product="gcp", service="gcp.audit")


@dataclass
class PipelineWasUsed(RuleProcessingCondition):
    pipeline: Optional[str] = field(default=None)

    def match(self, pipeline: ProcessingPipeline, rule: SigmaRule) -> bool:
        cli_context = click.get_current_context(silent=True)
        return cli_context and self.pipeline in cli_context.params["pipeline"]


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
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["ParentCommandLine"])],
            ),
            ProcessingItem(
                transformation=FieldMappingTransformation(
                    {
                        "gcp.audit.method_name": "protoPayload.methodName",
                    }
                ),
                detection_item_conditions=[DetectionContainsFieldName()],
                rule_conditions=[logsource_gcp_audit()],
            ),
            ProcessingItem(
                transformation=FieldPrefixMappingTransformation(
                    {
                        "data.protoPayload": "protoPayload",
                    }
                ),
                detection_item_conditions=[DetectionContainsFieldName()],
                rule_conditions=[logsource_gcp_audit()],
            ),
        ],
        postprocessing_items=[QueryPostprocessingItem(transformation=SdYamlTransformation())],
    )
