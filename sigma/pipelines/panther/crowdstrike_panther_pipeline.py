from sigma.exceptions import SigmaConfigurationError, SigmaValueError
from sigma.pipelines.common import (
    logsource_windows_dns_query,
    logsource_windows_network_connection,
    logsource_windows_network_connection_initiated,
    logsource_windows_process_creation,
)
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    AddConditionTransformation,
    AddFieldnamePrefixTransformation,
    ChangeLogsourceTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
    ValueTransformation,
)
from sigma.types import SigmaNumber, SigmaType

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


class StrToIntValueTransformation(ValueTransformation):
    def apply_value(self, field: str, val: SigmaType) -> SigmaType:
        try:
            return SigmaNumber(str(val))
        except (TypeError, SigmaValueError):
            raise SigmaConfigurationError(
                f"Value '{val}' can't be converted to number for {str(self)}"
            )


def crowdstrike_panther_pipeline():
    crowdstrike_pipeline = ProcessingPipeline(
        name="Generic Log Sources to CrowdStrike Falcon Data Replicator (FDR) Transformation",
        priority=10,
        postprocessing_items=[QueryPostprocessingItem(transformation=SdYamlTransformation())],
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
            ProcessingItem(
                identifier="cs_parentbasefilename_executable_only",
                transformation=ReplaceStringTransformation(
                    regex=".*\\\\(.+)$",
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
                        "sha256": "SHA256HashData",
                        "sha1": "SHA1HashData",
                        "ParentImage": "ParentBaseFileName",
                        "Image": "ImageFileName",
                        "md5": "MD5HashData",
                    }
                ),
            ),
            ProcessingItem(
                transformation=AddFieldnamePrefixTransformation(prefix="event."),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "CommandLine",
                            "DomainName",
                            "ImageFileName",
                            "IP4Records",
                            "MD5HashData",
                            "ParentBaseFileName",
                            "RemoteAddressIP4",
                            "RemotePort",
                            "SHA1HashData",
                            "SHA256HashData",
                            "TargetFilename",
                        ]
                    ),
                ],
            ),
            ProcessingItem(
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["DestinationHostname"])],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "1"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value="ICMP",
                    ),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "6"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value="TCP",
                    ),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "17"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value="UDP",
                    ),
                ],
            ),
            ProcessingItem(
                transformation=AddConditionTransformation({"event.Protocol": "58"}),
                rule_conditions=[
                    RuleIContainsDetectionItemCondition(
                        field="Protocol",
                        value="IPv6-ICMP",
                    ),
                ],
            ),
            ProcessingItem(
                transformation=StrToIntValueTransformation(),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=["event.Protocol"],
                    )
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
                    "Rule type not currently supported by the CrowdStrike Sigma pipeline"
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
                    "Rule type not currently supported by the CrowdStrike Sigma pipeline"
                ),
                rule_condition_negation=True,
                rule_conditions=[
                    logsource_network_connection(),
                    logsource_process_creation(),
                    logsource_file_event(),
                ],
            ),
        ],
    )
    return crowdstrike_pipeline
