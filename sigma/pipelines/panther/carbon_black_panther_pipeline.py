from sigma.processing.conditions import IncludeFieldCondition, RuleContainsDetectionItemCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    AddConditionTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
)

from sigma.pipelines.panther.panther_pipeline import (
    logsource_file_event,
    logsource_linux,
    logsource_mac,
    logsource_network_connection,
    logsource_process_creation,
    logsource_windows,
)
from sigma.pipelines.panther.processing import RuleIContainsDetectionItemCondition
from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


def carbon_black_panther_pipeline():
    return ProcessingPipeline(
        name="Carbon Black Panther Pipeline",
        items=[
            ProcessingItem(
                transformation=AddConditionTransformation({"device_os": "WINDOWS"}),
                rule_conditions=[logsource_windows()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"device_os": "MAC"}),
                rule_conditions=[logsource_mac()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"device_os": "LINUX"}),
                rule_conditions=[logsource_linux()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"type": "endpoint.event.netconn"}),
                rule_conditions=[logsource_network_connection()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"type": "endpoint.event.filemod"}),
                rule_conditions=[logsource_file_event()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"type": "endpoint.event.procstart"}),
                rule_conditions=[logsource_process_creation()],
            ),
            ProcessingItem(
                transformation=FieldMappingTransformation(
                    {
                        "ParentImage": "parent_path",
                        "Image": "process_path",
                        "ParentCommandLine": "process_cmdline",
                        "CommandLine": "target_cmdline",
                        "TargetFilename": "filemod_name",
                        "DestinationIp": "remote_ip",
                        "DestinationPort": "remote_port",
                        "DestinationHostname": "netconn_domain",
                    }
                ),
            ),
            ProcessingItem(
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["OriginalFileName"])],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"netconn_inbound": "false"}),
                rule_conditions=[
                    RuleContainsDetectionItemCondition(
                        field="Initiated",
                        value="true",
                    ),
                ],
            ),
            ProcessingItem(
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=["Initiated"],
                    )
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"netconn_protocol": "PROTO_TCP"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value="tcp",
                    ),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"netconn_protocol": "PROTO_UDP"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value="udp",
                    ),
                ],
            ),
            ProcessingItem(
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=["Protocol"],
                    )
                ],
            ),
            ProcessingItem(
                identifier="cb_fail_not_implemented_rule_type",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation(
                    "Rule type not currently supported by the CarbonBlack Sigma pipeline"
                ),
                rule_condition_negation=True,
                rule_conditions=[
                    logsource_windows(),
                    logsource_mac(),
                    logsource_linux(),
                ],
            ),
            ProcessingItem(
                identifier="cb_fail_not_implemented_rule_type",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation(
                    "Rule type not currently supported by the CarbonBlack Sigma pipeline"
                ),
                rule_condition_negation=True,
                rule_conditions=[
                    logsource_network_connection(),
                    logsource_process_creation(),
                    logsource_file_event(),
                ],
            ),
        ],
        postprocessing_items=[QueryPostprocessingItem(transformation=SdYamlTransformation())],
    )
