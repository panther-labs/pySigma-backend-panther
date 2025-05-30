from abc import ABC, abstractmethod
from os import path
from typing import Any, List, Union

import click
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionValueExpression,
    ParentChainMixin,
)
from sigma.conversion.state import ConversionState


class BasePantherBackendHelper(ABC):
    @abstractmethod
    def update_parsed_conditions(
        self, condition: ParentChainMixin, negated: bool = False
    ) -> ParentChainMixin: ...

    @abstractmethod
    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any: ...

    @abstractmethod
    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any: ...

    @abstractmethod
    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any: ...

    @abstractmethod
    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any: ...

    @abstractmethod
    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any: ...

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any: ...

    @abstractmethod
    def convert_condition_or(self, key_cond_values: list) -> Any: ...

    @abstractmethod
    def simplify_convert_condition_and(self, key_cond_values: list) -> Any: ...

    @abstractmethod
    def convert_condition_and(self, key_cond_values: list) -> Any: ...

    @abstractmethod
    def convert_condition_not(self, key_cond_values: list) -> Any: ...

    @abstractmethod
    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any: ...

    @abstractmethod
    def _add_rule_suffix(self, query, file_name): ...

    @staticmethod
    def _add_rule_prefix(query, file_name):
        cli_context = click.get_current_context(silent=True)
        enabled_pipelines = cli_context.params["pipeline"]

        prefix = ""
        if "carbon_black_panther" in enabled_pipelines:
            prefix = "cb_"
        if "crowdstrike_panther" in enabled_pipelines:
            prefix = "cs_"
        if "sentinelone_panther" in enabled_pipelines:
            prefix = "s1_"
        if "sysmon_panther" in enabled_pipelines:
            prefix = "sysmon_"
        if (
            "windows_logsource_panther" in enabled_pipelines
            or "windows_audit_panther" in enabled_pipelines
        ):
            prefix = "win_"

        if prefix:
            file_name = prefix + file_name
            query["RuleID"] = prefix + query["RuleID"]

        return file_name

    def save_queries_into_individual_files(self, output_dir: str, queries: List[Any]):
        for query in queries:
            file_name = query["SigmaFile"]

            # SigmaFile should not be put into rule content
            query.pop("SigmaFile", None)

            file_name = self._add_rule_prefix(query, file_name)
            file_name = self._add_rule_suffix(query, file_name)

            file_name_without_extension = file_name[:-4]
            file_path = path.join(output_dir, file_name_without_extension)
            self.write_query_into_file(file_path, query)

    @abstractmethod
    def write_query_into_file(self, file_path_yml: str, query: Any): ...
