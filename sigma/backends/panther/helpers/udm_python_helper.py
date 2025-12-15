import re
from typing import Any, Union

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionValueExpression,
    ParentChainMixin,
)
from sigma.conversion.state import ConversionState

from sigma.backends.panther.helpers.base import BasePantherBackendHelper


def simplify(func):
    def inner(helper, key_cond_values) -> str:
        if len(key_cond_values) == 1:
            result = key_cond_values[0]
        else:
            result = func(helper, key_cond_values)
        return result

    return inner


class UdmPythonHelper(BasePantherBackendHelper):
    """
    Python helper that uses event.udm() for unified data model field access.

    This helper generates Panther Python rules that use event.udm("SigmaFieldName")
    instead of direct field access like event.deep_get(), allowing rules to work
    across multiple EDR platforms (SentinelOne, CrowdStrike, Carbon Black).
    """

    WILDCARD_SYMBOL = "*"

    @staticmethod
    def get_key_path_value(path: str):
        """
        Generate event.udm() accessor instead of event.deep_get().

        For example: "Image" becomes event.udm("Image", default="")
        """
        # Use event.udm() with the Sigma field name directly
        key_path_value = f'event.udm("{path}", default="")'
        return key_path_value

    def update_parsed_conditions(
        self, condition: ParentChainMixin, negated: bool = False
    ) -> ParentChainMixin:
        return condition

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any:
        keys = [x.field for x in cond.args]

        assert len(keys) and len(set(keys)) == 1
        return f"{self.get_key_path_value(keys[0])} in {[x.value.to_plain() for x in cond.args]}"

    @staticmethod
    def prepare_cond_value(initial_value: str) -> str:
        value = initial_value
        if "\\" in value:
            value = value.replace("\\", "\\\\")
        if '"' in value:
            value = value.replace('"', '\\"')
        return value

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = self.get_key_path_value(cond.field)
        value = str(cond.value)
        if value == self.WILDCARD_SYMBOL:
            return f"{key_path} != ''"
        value = self.prepare_cond_value(value)
        wildcards_count = value.count(self.WILDCARD_SYMBOL)
        if wildcards_count == 0:
            return f'{key_path}.lower() == "{value.lower()}"'
        if wildcards_count == 1:
            if value.startswith(self.WILDCARD_SYMBOL):
                return f'{key_path}.lower().endswith("{value[1:].lower()}")'
            if value.endswith(self.WILDCARD_SYMBOL):
                return f'{key_path}.lower().startswith("{value[:-1].lower()}")'
        if wildcards_count == 2:
            if value.startswith(self.WILDCARD_SYMBOL) and value.endswith(self.WILDCARD_SYMBOL):
                return f'"{value[1:-1].lower()}" in {key_path}.lower()'
        value = value.replace("*", ".*")
        return f're.match(r"^{value}$", {key_path}, re.IGNORECASE)'

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        # Remove the 'or ""' suffix for numeric comparisons
        key_path = f'event.udm("{cond.field}")'
        return f"{key_path} == {cond.value.to_plain()}"

    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = f'event.udm("{cond.field}")'
        return f"{key_path} is None or {key_path} == ''"

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = self.get_key_path_value(cond.field)
        value = str(cond.value.regexp)
        value = self.prepare_cond_value(value)
        return f're.match(r"{value}", {key_path}, re.IGNORECASE)'

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = self.get_key_path_value(cond.field)
        value = cond.value.cidr
        return f'ipaddress.ip_address({key_path}) in ipaddress.ip_network("{value}")'

    @simplify
    def convert_condition_or(self, key_cond_values: list) -> Any:
        return f"any([{', '.join(key_cond_values)}])"

    def simplify_convert_condition_and(self, key_cond_values: list) -> Any:
        simplified = []
        for key_cond_value in key_cond_values:
            if key_cond_value.startswith("all"):
                simplified.append(key_cond_value[5:-2])  # condition without 'all([' and '])'
            else:
                simplified.append(key_cond_value)
        return simplified

    @simplify
    def convert_condition_and(self, key_cond_values: list) -> Any:
        return f"all([{', '.join(key_cond_values)}])"

    def convert_condition_not(self, key_cond_values: list) -> Any:
        return "not " + ", ".join(key_cond_values)

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        value = self.prepare_cond_value(cond.value.to_plain())
        return f'"{value}" in json.dumps(event.to_dict())'

    def _add_rule_suffix(self, query, file_name):
        return file_name

    def write_query_into_file(self, file_path: str, query: Any):
        detection = query.pop("Detection", "pass")[0]
        file_path_python = file_path + ".py"
        file_path_yml = file_path + ".yml"
        query["Filename"] = file_path_python.split("/")[-1]
        with open(file_path_python, "w") as file:
            file.write(detection)
        with open(file_path_yml, "w") as file:
            yaml.dump(query, file)
