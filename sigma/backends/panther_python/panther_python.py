import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any

from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression


class PantherBackend(TextQueryBackend):
    """panther_python backend."""
    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html
    name: ClassVar[str] = "panther_python backend"
    formats: Dict[str, str] = {
        "default": "panther_python queries"
    }

    # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    requires_pipeline: bool = False


    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    # Reflect parse tree by putting parenthesis around all expressions - use this for target systems without strict precedence rules.
    parenthesize : bool = True

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = " == "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting

    # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    # before: ['\'event.get(\'fieldA\')\'=="valueA" and \'event.get(\'fieldB\')\'=="valueB"']
    # after:  ['event.get(\'fieldA\')=="valueA" and event.get(\'fieldB\')=="valueB"']
    # field_quote: ClassVar[str] = "'"
    field_quote: ClassVar[str] = ""
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\\w+$")  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    # field_escape: ClassVar[str] = "\\"
    field_escape: ClassVar[str] = ""
    field_escape_quote: ClassVar[bool] = True  # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Pattern] = re.compile("\\s")  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[str] = '"'  # string quoting character (added as escaping character)
    # Escaping character for special characters inside string
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = "\\"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "startswith"
    endswith_expression: ClassVar[str] = "endswith"
    contains_expression: ClassVar[str] = "contains"
    wildcard_match_expression: ClassVar[str] = "match"  # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    # re_expression: ClassVar[str] = "{field}=~{regex}"
    re_expression: ClassVar[str] = 're.compile(r"{regex}").search({field})'

    re_escape_char: ClassVar[str] = "\\"  # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"  # Character used as single wildcard

    # CIDR expression query as format string with placeholders {field} = {value}
    # cidr_expression: ClassVar[str] = "cidrmatch({field}, {value})"
    cidr_expression: ClassVar[str] = 'ipaddress.ip_address(event.get("field")) in ipaddress.ip_network("{value}")'

    cidr_in_list_expression: ClassVar[str] = "{field} in ({value})"  # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    field_null_expression: ClassVar[str] = "{field} is null"  # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = True  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.

    # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "{field} {op} [{list}]"
    or_in_operator: ClassVar[str] = "in"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    # and_in_operator: ClassVar[str] = "contains-all"  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = '"{value}"'  # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = '{value}'  # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[str] = '_=~{value}'  # Expression for regular expression not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = "\n| "  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[str] = "\n| "  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[str] = "*"  # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def finalize_query_panther_rule(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        # TODO: implement the per-query output for the output format panther_rule here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        # TODO: proper type annotation.
        return query

    def finalize_output_panther_rule(self, queries: List[str]) -> Any:
        # TODO: implement the output finalization for all generated queries for the format panther_rule here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        # TODO: proper type annotation. Sigma CLI supports:
        # - str: output as is.
        # - bytes: output in file only (e.g. if a zip package is output).
        # - dict: output serialized as JSON.
        # - list of str: output each item as is separated by two newlines.
        # - list of dict: serialize each item as JSON and output all separated by newlines.
        return "\n".join(queries)

    def escape_and_quote_field(self, field_name : str) -> str:
        field_name = f'event.get("{field_name}")'
        return super().escape_and_quote_field(field_name)