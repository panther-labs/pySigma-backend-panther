from sigma.pipelines.crowdstrike import crowdstrike_fdr_pipeline
from sigma.processing.conditions import IncludeFieldCondition, RuleContainsDetectionItemCondition
from sigma.processing.pipeline import ProcessingItem
from sigma.processing.transformations import (
    AddConditionTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
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
    crowdstrike_pipeline = crowdstrike_fdr_pipeline()
    crowdstrike_pipeline.postprocessing_items.append(SdYamlTransformation())

    crowdstrike_pipeline.items += [
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
    ]
    return crowdstrike_pipeline
