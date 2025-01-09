from http.cookiejar import deepvalues
from typing import Any, Union

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionValueExpression,
    ParentChainMixin,
)
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.panther.helpers.base import BasePantherBackendHelper

LOG_TYPES_MAP = {
    "Crowdstrike.FDREvent": "crowdstrike_fdrevent",
    "CarbonBlack.EndpointEvent": "carbonblack_endpointevent",
    "SentinelOne.DeepVisibilityV2": "sentinelone_deepvisibilityv2",
    "Windows.EventLogs": "windows_eventlogs",
    "Okta.SystemLog": "okta_systemlog",
    "AWS.CloudTrail": "aws_cloudtrail",
    "GitHub.Audit": "github_audit",
    "GCP.AuditLog": "gcp_auditlog",
}


class PantherFlowHelper(BasePantherBackendHelper):
    WILDCARD_SYMBOL = "*"

    def update_parsed_conditions(
        self, condition: ParentChainMixin, negated: bool = False
    ) -> ParentChainMixin:
        return condition

    @staticmethod
    def prepare_cond_value(initial_value: str) -> str:
        value = initial_value
        if "\\" in value:
            value = value.replace("\\", "\\\\")
        if "'" in value:
            value = value.replace("'", "'")
        return value

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any:
        keys = [x.field for x in cond.args]

        assert len(keys) and len(set(keys)) == 1
        return f"{keys[0]} in {[x.value.to_plain() for x in cond.args]}"

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = cond.field
        value = str(cond.value)
        if value == self.WILDCARD_SYMBOL:
            return f"{key_path} != ''"
        value = self.prepare_cond_value(value)
        wildcards_count = value.count(self.WILDCARD_SYMBOL)
        if wildcards_count == 0:
            return f"{key_path} == '{value}'"
        if wildcards_count == 1:
            if value.startswith(self.WILDCARD_SYMBOL):
                return f"strings.ends_with({key_path}, '{value[1:]}')"
            if value.endswith(self.WILDCARD_SYMBOL):
                return f"strings.starts_with({key_path}, '{value[:-1]}')"
        if wildcards_count == 2:
            if value.startswith(self.WILDCARD_SYMBOL) and value.endswith(self.WILDCARD_SYMBOL):
                return f"strings.contains({key_path}, '{value[1:-1]}')"
        value = value.replace("*", ".*")
        return f"re.matches({key_path}, '^{value}$')"

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{cond.field} == {cond.value.to_plain()}"

    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{cond.field} == ''"

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = cond.field
        value = str(cond.value.regexp)
        value = self.prepare_cond_value(value)
        return f"re.matches({key_path}, '{value}')"

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError("CIDR values are not supported in PantherFlow")

    def convert_condition_or(self, key_cond_values: list) -> Any:
        if len(key_cond_values) == 1:
            return key_cond_values[0]
        if len(key_cond_values) > 1:
            return "(\n      " + "\n    or ".join(key_cond_values).replace("\n", "\n  ") + "\n    )"
        else:
            return ""

    def simplify_convert_condition_and(self, key_cond_values: list) -> Any:
        return key_cond_values

    def convert_condition_and(self, key_cond_values: list) -> Any:
        if len(key_cond_values) > 0:
            return "\n    and ".join(key_cond_values)
        else:
            return ""

    def convert_condition_not(self, key_cond_values: list) -> Any:
        if len(key_cond_values) > 0:
            values = "".join(key_cond_values).replace("\n", "\n  ")
            return f"not (\n      {values}\n    )"
        else:
            return ""

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        value = self.prepare_cond_value(cond.value.to_plain())
        return f"search {value}"

    def _add_rule_suffix(self, query, file_name):
        return file_name

    def write_query_into_file(self, file_path: str, query: Any):
        detection = query.pop("Detection", "pass")[0]
        file_path_txt = file_path + ".txt"
        with open(file_path_txt, "w") as file:
            file.write(
                f"""{detection}
"""
            )
