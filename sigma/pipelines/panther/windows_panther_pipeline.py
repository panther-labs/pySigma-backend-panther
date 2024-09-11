from ast import Dict

from sigma.pipelines.common import generate_windows_logsource_items, logsource_windows
from sigma.processing.conditions import ExcludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    AddConditionTransformation,
    AddFieldnamePrefixTransformation,
    ChangeLogsourceTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
)

from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation

windows_generic_category_channel_mapping = {  # map generic windows log sources to windows channel
    "ps_module": {"service": "powershell", "EventID": 4103},
    "ps_script": {"service": "powershell", "EventID": 4104},
    "ps_classic_start": {"service": "powershell-classic", "EventID": 400},
    "ps_classic_provider_start": {"service": "powershell-classic", "EventID": 600},
    "ps_classic_script": {"service": "powershell-classic", "EventID": 800},
}

generic_logsource_to_windows_audit_event_mapping: Dict = (
    {  # map generic Sigma log sources to Windows audit log events for the windows_audit_pipeline
        "process_creation": {
            "EventID": 4688,
        },
        "registry_event": {
            "EventID": 4657,
            "OperationType": [
                "New registry value created",
                "Existing registry value modified",
            ],
        },
        "registry_set": {
            "EventID": 4657,
            "OperationType": "Existing registry value modified",
        },
        "registry_add": {
            "EventID": 4657,
            "OperationType": "New registry value created",
        },
    }
)


panther_windows_prefix = ProcessingItem(
    transformation=AddFieldnamePrefixTransformation(prefix="ExtraEventData."),
    field_name_conditions=[
        ExcludeFieldCondition(
            fields=[
                "ProcessID",
                "ThreadID",
                "TimeCreated",
                "EventID",
                "ProviderName",
                "ProviderGuid",
                "Qualifiers",
                "Version",
                "Level",
                "Task",
                "Opcode",
                "Keywords",
                "EventRecordID",
                "ActivityID",
                "RelatedActivityID",
                "Channel",
                "Computer",
                "UserID",
                "Message",
                "MessageTitle",
            ]
        ),
    ],
)


def windows_logsource_panther_pipeline() -> ProcessingPipeline:
    the_service = generate_windows_logsource_items(
        cond_field_template="Channel",
        cond_value_template="{source}",
    )

    the_category = [
        processing_item
        for category_name, info in windows_generic_category_channel_mapping.items()
        for processing_item in (
            ProcessingItem(
                identifier=f"windows_{category_name}_channel",
                transformation=AddConditionTransformation(
                    {
                        "EventID": info["EventID"],
                    }
                ),
                rule_conditions=[LogsourceCondition(category=category_name, product="windows")],
            ),
            ProcessingItem(
                identifier="windows_{category_name}_logsource",
                transformation=ChangeLogsourceTransformation(
                    product="windows", service=info["service"], category=category_name
                ),
                rule_conditions=[LogsourceCondition(category=category_name, product="windows")],
            ),
        )
    ] + [
        panther_windows_prefix,
        ProcessingItem(
            identifier="windows_fail_not_implemented_rule_type",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation(
                "Rule type not currently supported by the Windows Log Source pipeline"
            ),
            rule_condition_negation=True,
            rule_conditions=[
                LogsourceCondition(category=category_name, product="windows")
                for category_name in windows_generic_category_channel_mapping.keys()
            ]
            + [
                LogsourceCondition(service=info["service"])
                for info in windows_generic_category_channel_mapping.values()
            ],
        ),
    ]

    return ProcessingPipeline(
        name="Add Channel condition for Windows log sources",
        priority=10,
        items=the_category + the_service,
        postprocessing_items=[QueryPostprocessingItem(transformation=SdYamlTransformation())],
    )


def windows_audit_panther_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Map generic log sources to Windows audit logs",
        priority=10,
        items=[
            processing_item
            for logsource, conditions in generic_logsource_to_windows_audit_event_mapping.items()
            for processing_item in (
                ProcessingItem(
                    identifier=f"windows_{logsource}_condition",
                    transformation=AddConditionTransformation(conditions),
                    rule_conditions=[
                        LogsourceCondition(
                            category=logsource,
                            product="windows",
                        )
                    ],
                ),
                ProcessingItem(
                    identifier=f"windows_{logsource}_logsource",
                    transformation=ChangeLogsourceTransformation(
                        product="windows",
                        service="security",
                    ),
                    rule_conditions=[
                        LogsourceCondition(
                            category=logsource,
                            product="windows",
                        )
                    ],
                ),
            )
        ]
        + [
            ProcessingItem(
                identifier="windows_audit_fieldmappings",
                transformation=FieldMappingTransformation(
                    {
                        "Image": "NewProcessName",
                        "ParentImage": "ParentProcessName",
                        "Details": "NewValue",
                        "LogonId": "SubjectLogonId",
                    }
                ),
                rule_conditions=[
                    logsource_windows("security"),
                ],
            ),
            panther_windows_prefix,
            ProcessingItem(
                identifier="windows_fail_not_implemented_rule_type",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation(
                    "Rule type not currently supported by the Windows Audit pipeline"
                ),
                rule_condition_negation=True,
                rule_conditions=[logsource_windows("security")],
            ),
        ],
        postprocessing_items=[QueryPostprocessingItem(transformation=SdYamlTransformation())],
    )
