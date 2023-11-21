from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation, AddConditionTransformation

from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


def logsource_windows():
    return LogsourceCondition(product="windows")


def logsource_mac():
    return LogsourceCondition(product="mac")


def logsource_linux():
    return LogsourceCondition(product="linux")


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
                }),
                rule_conditions=[LogsourceCondition(category="file_event")]
            ),
            ProcessingItem(
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "NetworkConnectIP4", "NetworkConnectIP6", "NetworkReceiveAcceptIP4", "NetworkReceiveAcceptIP6"
                        ],
                    }
                ),
                rule_conditions=[LogsourceCondition(category="network_connection")]
            ),
        ],
        postprocessing_items=[
            SdYamlTransformation(),
        ]
    )
