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


class PythonHelper(BasePantherBackendHelper):
    WILDCARD_SYMBOL = "*"

    @staticmethod
    def simplify(func):
        def inner(helper, key_cond_values) -> str:
            if len(key_cond_values) == 1:
                result = key_cond_values[0]
            else:
                result = func(helper, key_cond_values)
            return result

        return inner

    @staticmethod
    def get_key_path_value(path: str):
        key_path = '"' + '", "'.join(path.split(".")) + '"'
        key_path_value = f"event.deep_get({key_path}, default='')"
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
            return f'{key_path} == "{value}"'
        if wildcards_count == 1:
            if value.startswith(self.WILDCARD_SYMBOL):
                return f'{key_path}.endswith("{value[1:]}")'
            if value.endswith(self.WILDCARD_SYMBOL):
                return f'{key_path}.startswith("{value[:-1]}")'
        if wildcards_count == 2:
            if value.startswith(self.WILDCARD_SYMBOL) and value.endswith(self.WILDCARD_SYMBOL):
                return f'"{value[1:-1]}" in {key_path}'
        value = value.replace("*", ".*")
        return f're.match(r"^{value}$", {key_path})'

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{self.get_key_path_value(cond.field)} == {cond.value.to_plain()}"

    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{self.get_key_path_value(cond.field)} == ''"

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = self.get_key_path_value(cond.field)
        value = str(cond.value.regexp)
        value = value.replace('"', '\\"')
        return f're.match(r"{value}", {key_path})'

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

    def write_queries_into_files(self, file_path_yml: str, query: Any):
        detection = query.pop("Detection", "pass")[0]
        file_path_python = file_path_yml[:-3] + "py"
        query["Filename"] = file_path_python.split("/")[-1]
        with open(file_path_python, "w") as file:
            file.write(detection)
        with open(file_path_yml, "w") as file:
            yaml.dump(query, file)
