from sigma.pipelines.common import (
    logsource_windows_dns_query,
    logsource_windows_network_connection,
    logsource_windows_network_connection_initiated,
    logsource_windows_process_creation,
)
from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    ChangeLogsourceTransformation,
    DetectionItemFailureTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    ReplaceStringTransformation,
)

from sigma.pipelines.panther.panther_sdyaml_pipeline import (
    logsource_file_event,
    logsource_linux,
    logsource_mac,
    logsource_network_connection,
    logsource_windows,
)
from sigma.pipelines.panther.processing import RuleIContainsDetectionItemCondition
from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


def crowdstrike_panther_pipeline():
    crowdstrike_pipeline = ProcessingPipeline(
        name="Generic Log Sources to CrowdStrike Falcon Data Replicator (FDR) Transformation",
        priority=10,
        postprocessing_items=[SdYamlTransformation()],
        items=[
            ProcessingItem(
                identifier="cs_process_creation_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": ["ProcessRollup2", "SyntheticProcessRollup2"],
                    }
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ],
            ),
            ProcessingItem(
                identifier="cs_process_creation_fieldmapping",
                transformation=FieldMappingTransformation(
                    {
                        "Image": "ImageFileName",
                        "ParentImage": "ParentBaseFileName",
                    }
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ],
            ),
            ProcessingItem(
                identifier="crowdstrike_process_creation_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="process_creation",
                    product="windows",
                    service="crowdstrike",
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ],
            ),
            # Network Connection
            ProcessingItem(
                identifier="cs_network_connection_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": "NetworkConnectionIP4",
                    }
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(True),
                ],
            ),
            ProcessingItem(
                identifier="cs_network_connection_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": "NetworkReceiveAcceptIP4",
                    }
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(False),
                ],
            ),
            ProcessingItem(
                identifier="cs_network_connection_fieldmapping",
                transformation=FieldMappingTransformation(
                    {
                        "DestinationIp": "RemoteAddressIP4",
                        "DestinationPort": "RemotePort",
                    }
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                ],
            ),
            ProcessingItem(
                identifier="cs_network_connection_drop_initiated",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_windows_network_connection(),
                ],
                field_name_conditions=[
                    IncludeFieldCondition(fields=["Initiated"]),
                ],
            ),
            ProcessingItem(
                identifier="crowdstrike_network_connection_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="network_connection",
                    product="windows",
                    service="crowdstrike",
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                ],
            ),
            # DNS Requests
            ProcessingItem(
                identifier="cs_dns_query_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": "DnsRequest",
                    }
                ),
                rule_conditions=[
                    logsource_windows_dns_query(),
                ],
            ),
            ProcessingItem(
                identifier="cs_dns_query_fieldmapping",
                transformation=FieldMappingTransformation(
                    {
                        "QueryName": "DomainName",
                        "QueryResults": "IP4Records",
                    }
                ),
                rule_conditions=[
                    logsource_windows_dns_query(),
                ],
            ),
            ProcessingItem(
                identifier="cs_dns_query_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="dns_query",
                    product="windows",
                    service="crowdstrike",
                ),
                rule_conditions=[
                    logsource_windows_dns_query(),
                ],
            ),
            # ParentBaseFileName handling
            ProcessingItem(
                identifier="cs_parentbasefilename_fail_completepath",
                transformation=DetectionItemFailureTransformation(
                    "Only file name of parent image is available in CrowdStrike events."
                ),
                field_name_conditions=[
                    IncludeFieldCondition(fields=["ParentBaseFileName"]),
                ],
                detection_item_conditions=[
                    MatchStringCondition(
                        cond="any",
                        pattern="^\\*\\\\?[^\\\\]+$",
                        negate=True,
                    )
                ],
            ),
            ProcessingItem(
                identifier="cs_parentbasefilename_executable_only",
                transformation=ReplaceStringTransformation(
                    regex="^\\*\\\\([^\\\\]+)$",
                    replacement="\\1",
                ),
                field_name_conditions=[
                    IncludeFieldCondition(fields=["ParentBaseFileName"]),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation(
                    {
                        "event_platform": "Windows",
                    }
                ),
                rule_conditions=[
                    logsource_windows(),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation(
                    {
                        "event_platform": "Mac",
                    }
                ),
                rule_conditions=[logsource_mac()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation(
                    {
                        "event_platform": "Linux",
                    }
                ),
                rule_conditions=[logsource_linux()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": "FileOpenInfo",
                    }
                ),
                rule_conditions=[logsource_file_event()],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "NetworkConnectIP4",
                            "NetworkConnectIP6",
                            "NetworkReceiveAcceptIP4",
                            "NetworkReceiveAcceptIP6",
                        ],
                    }
                ),
                rule_conditions=[logsource_network_connection()],
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
                        "TargetFileName": "event.TargetFileName",
                    }
                ),
            ),
            ProcessingItem(
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["DestinationHostname"])],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "ICMP"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value=1,
                    ),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "TCP"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value=6,
                    ),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "UDP"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value=17,
                    ),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "IPv6-ICMP"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value=58,
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
        ],
    )
    return crowdstrike_pipeline
