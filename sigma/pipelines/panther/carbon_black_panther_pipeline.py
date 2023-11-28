from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DropDetectionItemTransformation

from sigma.pipelines.panther.panther_sdyaml_pipeline import logsource_mac, logsource_windows, logsource_linux, logsource_network_connection, logsource_process_creation, logsource_file_event


def carbon_black_panther_pipeline():
    return ProcessingPipeline(
        name="Carbon Black Panther Pipeline",
        items=[
            ProcessingItem(transformation=AddConditionTransformation({"device_os": "WINDOWS"}), rule_conditions=[logsource_windows()]),
            ProcessingItem(transformation=AddConditionTransformation({"device_os": "MAC"}), rule_conditions=[logsource_mac()]),
            ProcessingItem(transformation=AddConditionTransformation({"device_os": "LINUX"}), rule_conditions=[logsource_linux()]),
            ProcessingItem(
                transformation=AddConditionTransformation({"type": "endpoint.event.netconn"}),
                rule_conditions=[logsource_network_connection()]
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"type": "endpoint.event.filemod"}), rule_conditions=[logsource_file_event()]
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"type": "endpoint.event.procstart"}),
                rule_conditions=[logsource_process_creation()]
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
                        "Protocol": "netconn_protocol",
                    }
                ),
            ),
            ProcessingItem(
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["OriginalFileName"])]
            ),
        ]
    )
