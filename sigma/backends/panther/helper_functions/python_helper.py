from typing import Any, Union

import yaml
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR, ConditionAND
from sigma.conversion.state import ConversionState


class PythonHelper:
    def get_key_path_value(self, path: str):
        key_path = '"' + '", '.join(path.split('.')) + '"'
        key_path_value = f"deep_walk(event, {key_path})"
        return key_path_value

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any:
        keys = [x.field for x in cond.args]

        assert len(keys) and len(set(keys)) == 1
        return f"{self.get_key_path_value(keys[0])} in {[x.value.to_plain() for x in cond.args]}"

    def convert_condition_field_eq_val_str(
            self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{self.get_key_path_value(cond.field)} == \"{str(cond.value)}\""

    def convert_condition_field_eq_val_num(
            self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{self.get_key_path_value(cond.field)} == \"{cond.value.to_plain()}\""

    def convert_condition_field_eq_val_null(
            self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return f"{self.get_key_path_value(cond.field)} is None"

    def save_queries_into_files(self, file_path_yml: str, query: Any):
        detection = query.pop("Detection", "pass")[0]
        file_path_python = file_path_yml[:-3] + "py"
        query["Filename"] = file_path_python.split("/")[-1]
        with open(file_path_yml, "w") as file:
            yaml.dump(query, file)
        with open(file_path_python, "w") as file:
            file.write(detection)

    def convert_condition_or(self, key_cond_values: list) -> Any:
        return f"any({','.join(key_cond_values)})"

    def simplify_convert_condition_and(self, key_cond_values) -> Any:
        simplified = []
        for key_cond_value in key_cond_values:
            if key_cond_value.startswith("all"):
                simplified.append(key_cond_value[3:-1])
            else:
                simplified.append(key_cond_value)
        return simplified

    def convert_condition_and(self, key_cond_values: list) -> Any:
        simplified_key_cond_values = self.simplify_convert_condition_and(key_cond_values)

        return f"all({', '.join(simplified_key_cond_values)})"
