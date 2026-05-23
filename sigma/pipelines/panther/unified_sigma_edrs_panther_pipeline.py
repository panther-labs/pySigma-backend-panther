from sigma.processing.conditions import LogsourceCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    AddConditionTransformation,
    ChangeLogsourceTransformation,
    RuleFailureTransformation,
)

from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


def unified_sigma_edrs_panther_pipeline() -> ProcessingPipeline:
    """
    Unified Sigma to Panther pipeline for multiple EDR platforms.

    This pipeline converts Sigma rules to Panther rules using event.udm() for field access,
    allowing a single rule to work across SentinelOne, CrowdStrike, and Carbon Black EDRs.

    Key differences from platform-specific pipelines:
    - No field mapping: Sigma fields are kept as-is (e.g., "Image" stays "Image")
    - Field access uses event.udm("FieldName") instead of direct field access
    - Works with data models that map Sigma fields to native EDR fields
    - Generates rules that work across all three EDR platforms

    Supported Sigma field categories:
    - Process creation fields (Image, CommandLine, User, ProcessId, etc.)
    - Hash fields (md5, sha1, sha256)
    - Network fields (DestinationIp, DestinationPort, SourceIp, etc.)
    - DNS fields (QueryName, query)
    - File fields (TargetFilename)

    The generated rules should be used with:
    - SentinelOne.DeepVisibility log type with sentinelone_data_model
    - Crowdstrike.FDREvent log type with crowdstrike_fdr_data_model
    - CarbonBlack.EndpointEvent log type with carbonblack_endpoint_data_model
    """

    # Operating system filters using normalized _os field
    os_filters = [
        # Windows OS
        ProcessingItem(
            identifier="unified_edr_windows",
            transformation=AddConditionTransformation({"_os": "windows"}),
            rule_conditions=[LogsourceCondition(product="windows")],
        ),
        # Linux OS
        ProcessingItem(
            identifier="unified_edr_linux",
            transformation=AddConditionTransformation({"_os": "linux"}),
            rule_conditions=[LogsourceCondition(product="linux")],
        ),
        # macOS
        ProcessingItem(
            identifier="unified_edr_macos",
            transformation=AddConditionTransformation({"_os": "macos"}),
            rule_conditions=[LogsourceCondition(product="macos")],
        ),
    ]

    # Event category filters using normalized _event_category field
    event_category_filters = [
        # Process creation
        ProcessingItem(
            identifier="unified_edr_process_creation",
            transformation=AddConditionTransformation({"_event_category": "process_creation"}),
            rule_conditions=[LogsourceCondition(category="process_creation")],
        ),
        # File events
        ProcessingItem(
            identifier="unified_edr_file_event",
            transformation=AddConditionTransformation({"_event_category": "file_event"}),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
            ],
        ),
        # Image load / Module load
        ProcessingItem(
            identifier="unified_edr_image_load",
            transformation=AddConditionTransformation({"_event_category": "image_load"}),
            rule_conditions=[LogsourceCondition(category="image_load")],
        ),
        # Pipe creation
        ProcessingItem(
            identifier="unified_edr_pipe_creation",
            transformation=AddConditionTransformation({"_event_category": "pipe_creation"}),
            rule_conditions=[LogsourceCondition(category="pipe_creation")],
        ),
        # Registry events
        ProcessingItem(
            identifier="unified_edr_registry",
            transformation=AddConditionTransformation({"_event_category": "registry_event"}),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
            ],
        ),
        # DNS queries
        ProcessingItem(
            identifier="unified_edr_dns",
            transformation=AddConditionTransformation({"_event_category": "dns_query"}),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns"),
            ],
        ),
        # Network connections
        ProcessingItem(
            identifier="unified_edr_network",
            transformation=AddConditionTransformation({"_event_category": "network_connection"}),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall"),
            ],
        ),
    ]

    # Change logsource to unified EDR service
    change_logsource_info = [
        ProcessingItem(
            identifier="unified_edr_logsource",
            transformation=ChangeLogsourceTransformation(service="unified_edr"),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="image_load"),
                LogsourceCondition(category="pipe_creation"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="dns"),
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall"),
            ],
        ),
    ]

    # Fail on unsupported rule types
    unsupported_rule_types = [
        ProcessingItem(
            identifier="unified_edr_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation(
                "Rule type not supported by the Unified Sigma EDR pipeline"
            ),
            rule_condition_negation=True,
            rule_conditions=[RuleProcessingItemAppliedCondition("unified_edr_logsource")],
        )
    ]

    return ProcessingPipeline(
        name="Unified Sigma EDR Panther Pipeline",
        priority=10,
        items=[
            *os_filters,
            *event_category_filters,
            *change_logsource_info,
            *unsupported_rule_types,
        ],
        postprocessing_items=[QueryPostprocessingItem(transformation=SdYamlTransformation())],
    )
