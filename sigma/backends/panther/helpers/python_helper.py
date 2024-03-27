from typing import Any, Union

import yaml
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionOR
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.panther.helpers.base import BasePantherBackendHelper


class PythonHelper(BasePantherBackendHelper):
    WILDCARD_SYMBOL = "*"

    @staticmethod
    def invert_if_needed(func):
        def inner(helper, cond, state):
            negated = getattr(cond, "negated", False)
            if negated:
                result = "not " + func(helper, cond, state)
            else:
                result = func(helper, cond, state)
            return result

        return inner

    @staticmethod
    def get_key_path_value(path: str):
        key_path = '"' + '", "'.join(path.split(".")) + '"'
        key_path_value = f"event.deep_get({key_path}, default='')"
        return key_path_value

    @invert_if_needed
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

    @invert_if_needed
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

    @invert_if_needed
    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f'{self.get_key_path_value(cond.field)} == "{cond.value.to_plain()}"'

    @invert_if_needed
    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{self.get_key_path_value(cond.field)} == ''"

    @invert_if_needed
    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        key_path = self.get_key_path_value(cond.field)
        value = str(cond.value.regexp)
        value = value.replace('"', '\\"')
        return f're.match(r"{value}", {key_path})'

    def convert_condition_or(self, key_cond_values: list) -> Any:
        if all("not" in value for value in key_cond_values):
            key_cond_values = [value.replace("not ", "") for value in key_cond_values]
            return f"not all([{', '.join(key_cond_values)}])"
        return f"any([{', '.join(key_cond_values)}])"

    def simplify_convert_condition_and(self, key_cond_values: list) -> Any:
        simplified = []
        for key_cond_value in key_cond_values:
            if key_cond_value.startswith("all"):
                simplified.append(key_cond_value[5:-2])  # condition without 'all([' and '])'
            else:
                simplified.append(key_cond_value)
        return simplified

    def convert_condition_and(self, key_cond_values: list) -> Any:
        return f"all([{', '.join(key_cond_values)}])"

    def save_queries_into_files(self, file_path_yml: str, query: Any):
        detection = query.pop("Detection", "pass")[0]
        file_path_python = file_path_yml[:-3] + "py"
        query["Filename"] = file_path_python.split("/")[-1]
        with open(file_path_python, "w") as file:
            file.write(detection)
        with open(file_path_yml, "w") as file:
            yaml.dump(query, file)
