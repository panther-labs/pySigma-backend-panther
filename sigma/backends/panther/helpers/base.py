from abc import ABC, abstractmethod
from typing import Any, Union

from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionOR
from sigma.conversion.state import ConversionState


class BasePantherBackendHelper(ABC):
    @abstractmethod
    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any:
        ...

    @abstractmethod
    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        ...

    @abstractmethod
    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        ...

    @abstractmethod
    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        ...

    @abstractmethod
    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        ...

    @abstractmethod
    def convert_condition_or(self, key_cond_values: list) -> Any:
        ...

    @abstractmethod
    def simplify_convert_condition_and(self, key_cond_values: list) -> Any:
        ...

    @abstractmethod
    def convert_condition_and(self, key_cond_values: list) -> Any:
        ...

    @abstractmethod
    def save_queries_into_files(self, file_path_yml: str, query: Any):
        ...
