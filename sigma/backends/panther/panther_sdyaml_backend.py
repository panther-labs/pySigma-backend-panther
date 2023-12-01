from os import path
from typing import Any, ClassVar, Dict, Iterable, List, Optional, Tuple, Union

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
    ParentChainMixin,
)
from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaString, SpecialChars


class PantherSdyamlBackend(Backend):
    # `output_dir` param should be used for saving each rule into separate file
    # `sigma convert -t panther_sdyaml -O output_dir=/tmp/directory`
    output_dir: Optional[str] = None

    name: ClassVar[str] = "panther sdyaml backend"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = True

    SDYAML_CONDITION_EXISTS = "Exists"
    SDYAML_CONDITION_EQUALS = "Equals"
    SDYAML_CONDITION_STARTS_WITH = "StartsWith"
    SDYAML_CONDITION_ENDS_WITH = "EndsWith"
    SDYAML_CONDITION_CONTAINS = "Contains"
    SDYAML_ALL = "All"
    SDYAML_ANY = "Any"
    SDYAML_IS_NULL = "IsNull"
    SDYAML_IS_IN = "IsIn"

    Inverted_Conditions = {
        SDYAML_CONDITION_EXISTS: "DoesNotExist",
        SDYAML_CONDITION_EQUALS: "DoesNotEqual",
        SDYAML_CONDITION_STARTS_WITH: "DoesNotStartWith",
        SDYAML_CONDITION_ENDS_WITH: "DoesNotEndWith",
        SDYAML_CONDITION_CONTAINS: "DoesNotContain",
    }

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        output_dir: Optional[str] = "",
    ):
        super().__init__(processing_pipeline, collect_errors)

        if output_dir:
            # relative path to absolute
            output_dir = path.abspath(path.expanduser(output_dir))
            if not path.isdir(output_dir):
                raise SigmaConfigurationError(f"{output_dir} is not a directory")
            self.output_dir = output_dir

    def get_key_condition_values(self, cond, state):
        rv = (self.convert_condition(arg, state) for arg in cond.args)  # generator object

        return list(rv)

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Any:
        key_cond_values = self.get_key_condition_values(cond, state)

        return {self.SDYAML_ALL: key_cond_values}

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Any:
        key_cond_values = self.get_key_condition_values(cond, state)

        return {self.SDYAML_ANY: key_cond_values}

    def invert_kcv(self, key_cond_value):
        rv = key_cond_value.copy()
        if "Condition" not in rv:
            raise SigmaFeatureNotSupportedByBackendError("Cannot invert this condition yet")

        if rv["Condition"] not in self.Inverted_Conditions:
            raise SigmaFeatureNotSupportedByBackendError(
                f"Inverted condition not implemented: '{rv['Condition']}'"
            )

        rv["Condition"] = self.Inverted_Conditions[rv["Condition"]]
        return rv

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Any:
        raise SigmaFeatureNotSupportedByBackendError(
            "NOT is handled within convert_condition_field_eq_val_str - If you see this message, please report the bug and how to reproduce it"
        )

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any:
        keys = [x.field for x in cond.args]

        assert len(keys) and len(set(keys)) == 1
        return {
            "KeyPath": keys[0],
            "Condition": self.SDYAML_IS_IN,
            "Values": [x.value.to_plain() for x in cond.args],
        }

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Dict:
        """Conversion of field = string value expressions"""

        # cond.value.startswith / endswith: Wants SigmaString, but is typed as base SigmaType
        conditions_and_rv_values = self.handle_wildcards(cond.value)

        rv = []

        for condition, rv_value in conditions_and_rv_values:
            key_cond_val = self.generate_sdyaml_key_cond_value(cond, state, condition, rv_value)
            rv.append(key_cond_val)
        if len(rv) > 1:
            return {self.SDYAML_ALL: rv}
        return rv[0]

    def generate_sdyaml_key_cond_value(self, sigma_cond, state, sdyaml_condition, rv_value):
        # Todo: Official "not preprocessing" flag will be supported later and invert the conditions
        #   https://github.com/SigmaHQ/pySigma/discussions/80
        negated = getattr(
            sigma_cond, "negated", False
        )  # We kind of hackily added 'negated' onto the object in update_parsed_conditions, so need to do this
        if negated:
            if sdyaml_condition not in self.Inverted_Conditions:
                raise SigmaFeatureNotSupportedByBackendError(
                    f"Inverted condition not implemented: '{sdyaml_condition}'"
                )

            sdyaml_condition = self.Inverted_Conditions[sdyaml_condition]

        rv = {"KeyPath": sigma_cond.field, "Condition": sdyaml_condition}

        if rv_value is not None:  # 'Exists' etc. have no value
            rv["Value"] = self.convert_value_str(rv_value, state)

        return rv

    def handle_wildcards(self, cond_value: SigmaString) -> Iterable[Tuple[str, SigmaString]]:
        condition = self.SDYAML_CONDITION_EQUALS
        rv_value = cond_value

        is_exists = len(cond_value) == 1 and cond_value.s[0] == SpecialChars.WILDCARD_MULTI  # ['*']
        is_starts_with = cond_value.endswith(SpecialChars.WILDCARD_MULTI)  # ['*', 'banana']
        is_ends_with = cond_value.startswith(SpecialChars.WILDCARD_MULTI)  # ['banana', '*']
        is_contains = is_starts_with and is_ends_with  # ['*', 'banana', '*']

        too_many_wildcards__not_contains = (
            cond_value.s.count(SpecialChars.WILDCARD_MULTI) > 1 and not is_contains
        )
        too_many_wildcards__is_contains = (
            cond_value.s.count(SpecialChars.WILDCARD_MULTI) > 2 and is_contains
        )
        if too_many_wildcards__not_contains or too_many_wildcards__is_contains:
            raise SigmaFeatureNotSupportedByBackendError(
                f'This configuration of wildcards currently not supported: "[{cond_value}]" in sdyaml'
            )

        # rv_value: remove the SpecialChars.WILDCARD_MULTI
        if is_exists:
            condition = self.SDYAML_CONDITION_EXISTS
            rv_value = None
        elif is_contains:
            condition = self.SDYAML_CONDITION_CONTAINS
            rv_value = cond_value[1:-1]
        elif is_starts_with:
            condition = self.SDYAML_CONDITION_STARTS_WITH
            rv_value = cond_value[:-1]
        elif is_ends_with:
            condition = self.SDYAML_CONDITION_ENDS_WITH
            rv_value = cond_value[1:]
        elif cond_value.contains_special():  # string like 'blah*banana'
            # we want to be really sure there's just 1 wildcard
            if cond_value.s.count(SpecialChars.WILDCARD_MULTI) > 1:
                raise SigmaFeatureNotSupportedByBackendError(
                    f"This configuration of wildcards currently not supported: [{cond_value}]"
                )

            # todo: Can this be handled more natively within SigmaString? I didn't find a way at a quick glance
            parts = cond_value.original.split("*")
            rv_value_starts_with = parts[0]
            rv_value_ends_with = parts[1]

            return [
                (self.SDYAML_CONDITION_STARTS_WITH, SigmaString(rv_value_starts_with)),
                (self.SDYAML_CONDITION_ENDS_WITH, SigmaString(rv_value_ends_with)),
            ]

        return [(condition, rv_value)]

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return {
            "KeyPath": cond.field,
            "Condition": self.SDYAML_CONDITION_EQUALS,
            "Value": cond.value.to_plain(),
        }

    def convert_condition_field_eq_field(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_field_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_field_not_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError("Regexp is not suppoerted in sdyaml")

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise (SigmaFeatureNotSupportedByBackendError())

    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return {"KeyPath": cond.field, "Condition": self.SDYAML_IS_NULL}

    def convert_condition_field_eq_query_expr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError(
            f'Search without specifying a Key is not supported: "{cond.value.to_plain()}".'
        )

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError("Enums are not supported right now")

    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_condition_query_expr(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    @staticmethod
    def convert_value_str(s: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""
        return s.convert()

    def update_parsed_conditions(
        self, condition: ParentChainMixin, negated: bool = False
    ) -> ParentChainMixin:
        """
        https://github.com/grafana/pySigma-backend-loki/blob/0b65eddf89aa40a20163ca94e8ff6717bed62610/sigma/backends/loki/loki.py#L573
        Do a depth-first recursive search of the parsed items and update conditions
        to meet SDYAML's structural requirements:

        - SDYAML does not support NOT operators, so we use De Morgan's law to push the
          negation down the tree (flipping ANDs and ORs and swapping operators, i.e.,
          = becomes !=, etc.)
        """
        if isinstance(condition, ConditionItem):
            if isinstance(condition, ConditionNOT):
                negated = not negated
                # Remove the ConditionNOT as the parent
                condition.args[0].parent = condition.parent
                return self.update_parsed_conditions(condition.args[0], negated)
            elif isinstance(condition, (ConditionAND, ConditionOR)):
                if negated:
                    if isinstance(condition, ConditionAND):
                        newcond = ConditionOR(condition.args, condition.source)
                    elif isinstance(condition, ConditionOR):
                        newcond = ConditionAND(condition.args, condition.source)
                    # Update the parent references to reflect the new structure
                    newcond.parent = condition.parent
                    for i in range(len(condition.args)):
                        condition.args[i].parent = newcond
                        condition.args[i] = self.update_parsed_conditions(
                            condition.args[i], negated
                        )
                    setattr(newcond, "negated", negated)
                    return newcond
                else:
                    for i in range(len(condition.args)):
                        condition.args[i] = self.update_parsed_conditions(
                            condition.args[i], negated
                        )
        # Record negation appropriately
        # NOTE: the negated property does not exist on the above classes,
        # so using setattr to set it dynamically
        setattr(condition, "negated", negated)
        return condition

    def convert_rule(self, rule: SigmaRule, output_format: Optional[str] = None) -> List[Any]:
        """
        Copy-pasted base class convert_rule, with the addition of update_parsed_conditions
        """
        state = ConversionState()
        try:
            self.last_processing_pipeline = (
                self.backend_processing_pipeline
                + self.processing_pipeline
                + self.output_format_processing_pipeline[output_format or self.default_format]
            )

            error_state = "applying processing pipeline on"
            self.last_processing_pipeline.apply(rule)  # 1. Apply transformations
            state.processing_state = self.last_processing_pipeline.state

            # 1.5. Apply SDYAML parse tree changes BEFORE attempting to convert a rule
            # When finalising a query from a condition, the index it is associated with
            # is the index of the parsed_condition from the rule detection. As this
            # code may partition one or more of these conditions into multiple
            # conditions, we explicitly associate them together here so the
            # relationship can be maintained throughout.
            conditions = [
                (index, self.update_parsed_conditions(cond.parsed))
                for index, cond in enumerate(rule.detection.parsed_condition)
            ]

            error_state = "converting"

            queries = [  # 2. Convert condition
                self.convert_condition(cond, state) for index, cond in conditions
            ]

            error_state = "finalizing query for"
            rv = [  # 3. Postprocess generated query
                self.finalize_query(rule, query, index, state, output_format or self.default_format)
                for index, query in enumerate(queries)
            ]
            return rv
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            raise e
        except (
            Exception
        ) as e:  # enrich all other exceptions with Sigma-specific context information
            error_state = e
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            elif len(e.args) == 0:
                e.args = (msg,)
            else:
                e.args = (e.args[0] + msg,)
            raise

    def save_queries_into_individual_files(self, queries: List[Any]):
        for query in queries:
            file_path = path.join(self.output_dir, query["SigmaFile"])
            with open(file_path, "w") as file:
                query.pop("SigmaFile", None)
                yaml.dump(query, file)

    def finalize_output_default(self, queries: List[Any]) -> Any:
        if self.output_dir:
            self.save_queries_into_individual_files(queries)
        # cleanup of SigmaFile key
        for query in queries:
            query.pop("SigmaFile", None)
        if len(queries) == 1:
            return yaml.dump(queries[0])
        return yaml.dump(queries)
