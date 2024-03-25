from os import path
from typing import Any, ClassVar, Dict, List, Optional, Union

import black
import click
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
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

from sigma.backends.panther.helpers.python_helper import PythonHelper
from sigma.backends.panther.helpers.sdyaml_helper import SDYAMLHelper


class PantherBackend(Backend):
    # `output_dir` param should be used for saving each rule into separate file
    # `sigma convert -t panther_sdyaml -O output_dir=/tmp/directory`
    output_dir: Optional[str] = None

    name: ClassVar[str] = "panther sdyaml backend"

    default_format: ClassVar[str] = "sdyaml"
    formats = {
        "default": "sdyaml",
        "sdyaml": "sdyaml",
        "python": "python",
    }
    output_format_processing_pipeline = {
        "default": ProcessingPipeline(),
        "sdyaml": ProcessingPipeline(),
        "python": ProcessingPipeline(),
    }

    format_helpers = {
        "default": SDYAMLHelper(),
        "sdyaml": SDYAMLHelper(),
        "python": PythonHelper(),
    }

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = True

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

    def simplify_convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Any:
        key_cond_values = self.get_key_condition_values(cond, state)
        return self.format_helper.simplify_convert_condition_and(key_cond_values)

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Any:
        simplified_key_cond_values = self.simplify_convert_condition_and(cond, state)
        return self.format_helper.convert_condition_and(simplified_key_cond_values)

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Any:
        key_cond_values = self.get_key_condition_values(cond, state)

        return self.format_helper.convert_condition_or(key_cond_values)

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Any:
        raise SigmaFeatureNotSupportedByBackendError(
            "NOT is handled within convert_condition_field_eq_val_str - If you see this message, please report the bug and how to reproduce it"
        )

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any:
        return self.format_helper.convert_condition_as_in_expression(cond, state)

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Dict:
        return self.format_helper.convert_condition_field_eq_val_str(cond, state)

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        return self.format_helper.convert_condition_field_eq_val_num(cond, state)

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
        return self.format_helper.convert_condition_field_eq_val_re(cond, state)

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
        return self.format_helper.convert_condition_field_eq_val_null(cond, state)

    def convert_condition_field_eq_query_expr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_correlation_event_count_rule(
        rule: "SigmaCorrelationRule", output_format: str | None = None, method: str | None = None
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_correlation_temporal_rule(
        rule: SigmaCorrelationRule, output_format: str | None = None, method: str | None = None
    ) -> List[Any]:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_correlation_value_count_rule(
        rule: SigmaCorrelationRule, output_format: str | None = None, method: str | None = None
    ) -> List[Any]:
        raise SigmaFeatureNotSupportedByBackendError()

    def convert_correlation_temporal_ordered_rule(
        rule: SigmaCorrelationRule, output_format: str | None = None, method: str | None = None
    ) -> List[Any]:
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
            self.format_helper = self.format_helpers[output_format or self.default_format]

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

    def _add_rule_suffix(self, query, file_name):
        suffix = "_simple"

        query["RuleID"] += suffix

        file_name_pieces = file_name.split(".")
        file_extension = file_name_pieces[-1]
        file_name = "".join(file_name_pieces[:-1])
        return f"{file_name}{suffix}.{file_extension}"

    def _add_rule_prefix(self, query, file_name):
        cli_context = click.get_current_context(silent=True)
        enabled_pipelines = cli_context.params["pipeline"]

        prefix = ""
        if "carbon_black_panther" in enabled_pipelines:
            prefix = "cb_"
        if "crowdstrike_panther" in enabled_pipelines:
            prefix = "cs_"
        if "sentinel_one_panther" in enabled_pipelines:
            prefix = "s1_"

        if prefix:
            file_name = prefix + file_name
            query["RuleID"] = prefix + query["RuleID"]

        return file_name

    def save_queries_into_individual_files(self, queries: List[Any]):
        for query in queries:
            file_name = query["SigmaFile"]

            # SigmaFile should not be put into rule content
            query.pop("SigmaFile", None)

            file_name = self._add_rule_prefix(query, file_name)
            file_name = self._add_rule_suffix(query, file_name)

            file_path_yml = path.join(self.output_dir, file_name)
            self.format_helper.save_queries_into_files(file_path_yml, query)

    def finalize_output_default(self, queries: List[Any]) -> Any:
        return self.finalize_output_sdyaml(queries)

    def finalize_output_sdyaml(self, queries):
        if self.output_dir:
            self.save_queries_into_individual_files(queries)
        # cleanup of SigmaFile key
        for query in queries:
            query.pop("SigmaFile", None)
        if len(queries) == 1:
            return yaml.dump(queries[0])
        return yaml.dump(queries)

    def finalize_output_python(self, queries):
        if self.output_dir:
            self.save_queries_into_individual_files(queries)
        if len(queries) == 1:
            return queries[0]
        return queries

    def finalize_query_sdyaml(
        self, rule: SigmaRule, query: Any, index: int, state: ConversionState
    ):
        return query

    def finalize_query_python(
        self, rule: SigmaRule, query: Any, index: int, state: ConversionState
    ):
        import_re = "import re\n\n\n" if "re." in query else ""
        query = (
            import_re
            + f"""def rule(event):
    if {query}:
        return True
    return False
        """
        )
        try:
            formatted_query = black.format_file_contents(
                src_contents=query, fast=True, mode=black.FileMode(line_length=100)
            )
            return formatted_query
        except black.parsing.InvalidInput:
            raise SigmaFeatureNotSupportedByBackendError(
                f"Invalid input for formatting python code: {query}"
            )
