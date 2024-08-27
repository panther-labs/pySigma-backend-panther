from .carbon_black_panther_pipeline import carbon_black_panther_pipeline
from .crowdstrike_panther_pipeline import crowdstrike_panther_pipeline
from .panther_pipeline import panther_pipeline
from .sentinelone_panther_pipeline import sentinelone_panther_pipeline
from .windows import windows_audit_pipeline, windows_logsource_pipeline

pipelines = {
    "windows-logsources": windows_logsource_pipeline,
    "windows-audit": windows_audit_pipeline,
}
