from sigma.conversion.state import ConversionState
from sigma.types import re, SigmaString, SigmaNumber
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.insight_idr import insight_idr_pipeline
from sigma.conversion.deferred import (
    DeferredQueryExpression,
    DeferredTextQueryExpression,
)
from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionAND,
)
from sigma.types import SigmaCompareExpression
from typing import Union, ClassVar, Optional, Tuple, List, Dict, Any


class InsightIDRBackend(TextQueryBackend):
    """InsightIDR LEQL backend."""

    name: ClassVar[str] = "Rapid7 InsightIDR Log Entry Query Language (LEQL) Queries"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Simple log search query mode",
        "leql_advanced_search": "Advanced Log Entry Query Language (LEQL) queries",
        "leql_detection_definition": "LEQL format roughly matching the 'Rule Logic' tab in ABA detection rule definition",
    }
    requires_pipeline: ClassVar[bool] = False

    # built-in pipeline
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = insight_idr_pipeline()

    # in-expressions
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = True  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        True  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )

    group_expression: ClassVar[str] = "({expr})"

    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    icontains_token: ClassVar[str] = "ICONTAINS"
    istarts_with_token: ClassVar[str] = "ISTARTS-WITH"

    str_double_quote: ClassVar[str] = '"'
    str_single_quote: ClassVar[str] = "'"
    str_triple_quote: ClassVar[str] = '"""'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"

    re_expression: ClassVar[str] = "{field}=/{regex}/i"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = '"'

    cidr_expression: ClassVar[str] = "{field} = IP({value})"

    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = "{field} = null"

    field_in_list_expression: ClassVar[str] = "{field} IIN [{list}]"
    icontains_any_expression: ClassVar[Optional[str]] = "{field} ICONTAINS-ANY [{list}]"
    icontains_all_expression: ClassVar[Optional[str]] = "{field} ICONTAINS-ALL [{list}]"
    istartswith_any_expression: ClassVar[Optional[str]] = (
        "{field} ISTARTS-WITH-ANY [{list}]"
    )
    list_separator: ClassVar[str] = ", "

    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"
    no_case_str_expression: ClassVar[str] = "NOCASE({value})"

    def get_quote_type(self, string_val):
        """Returns the shortest correct quote type (single, double, or trip) based on quote characters contained within an input string"""
        if '"' and "'" in string_val:
            quote = self.str_triple_quote
        elif '"' in string_val:
            quote = self.str_single_quote
        else:
            quote = self.str_double_quote

        return quote

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        field = cond.field
        val = cond.value.to_plain()
        val_no_wc = val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi)
        quote = self.get_quote_type(val)
        # contains
        if val.startswith(self.wildcard_single) and val.endswith(self.wildcard_single):
            result = (
                cond.field
                + self.token_separator
                + self.icontains_token
                + self.token_separator
                + quote
                + val_no_wc
                + quote
            )
        # startswith
        elif val.endswith(self.wildcard_single) and not val.startswith(
            self.wildcard_single
        ):
            result = (
                cond.field
                + self.token_separator
                + self.istarts_with_token
                + self.token_separator
                + quote
                + val_no_wc
                + quote
            )
        # endswith
        elif val.startswith(self.wildcard_single) and not val.endswith(
            self.wildcard_single
        ):
            escaped_val = re.escape(val_no_wc).replace(
                "/", "\\/"
            )  # re.escape is not escaping the forward slash correctly :(
            result = self.re_expression.format(
                field=field, regex=".*{}$".format(escaped_val)
            )
        # plain equals
        else:
            no_case_str = self.no_case_str_expression.format(
                value=quote + self.convert_value_str(cond.value, state) + quote
            )
            result = (
                cond.field
                + self.token_separator
                + self.eq_token
                + self.token_separator
                + no_case_str
            )

        return result

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        return self.re_expression.format(field=cond.field, regex=cond.value.regexp)

    def decide_convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> bool:
        """
        Decide if an OR or AND expression should be converted as "field in (value list) or startswith/contains any/all" or as plain expression.
        """
        # Check if conversion of condition type is enabled
        if (
            not self.convert_or_as_in
            and isinstance(cond, ConditionOR)
            or not self.convert_and_as_in
            and isinstance(cond, ConditionAND)
        ):
            return False

        # All arguments of the given condition must reference a field
        if not all(
            (isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args)
        ):
            return False

        # Build a set of all fields appearing in condition arguments
        fields = {arg.field for arg in cond.args}
        # All arguments must reference the same field
        if len(fields) != 1:
            return False

        # All argument values must be strings or numbers
        if not all(
            [isinstance(arg.value, (SigmaString, SigmaNumber)) for arg in cond.args]
        ):
            return False

        # Check for plain strings if wildcards are not allowed for string expressions.
        if not self.in_expressions_allow_wildcards and any(
            [
                arg.value.contains_special()
                for arg in cond.args
                if isinstance(arg.value, SigmaString)
            ]
        ):
            return False

        # All arguments must have the same modifier - use the wildcards to confirm this
        vals = [str(arg.value.to_plain() or "") for arg in cond.args]
        first_char = [char for char in "".join([val[0] for val in vals])]
        last_char = [char for char in "".join([val[-1] for val in vals])]
        # check for all-wildcard first character and mixed-wildcard last character
        if (
            all([char == self.wildcard_multi for char in first_char])
            and self.wildcard_multi in last_char
            and not all([char == self.wildcard_multi for char in last_char])
        ):
            return False
        # check for all-wildcard last character and mixed-wildcard first character
        if (
            all([char == self.wildcard_multi for char in last_char])
            and self.wildcard_multi in first_char
            and not all([char == self.wildcard_multi for char in first_char])
        ):
            return False

        # All checks passed, expression can be converted to in-expression
        return True

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        vals = [str(arg.value.to_plain() or "") for arg in cond.args]
        test_val = vals[0]
        vals_no_wc = [
            val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals
        ]
        vals_formatted = self.list_separator.join(
            [
                (
                    self.get_quote_type(v) + v + self.get_quote_type(v)
                    if isinstance(v, str)
                    else str(v)
                )
                for v in vals_no_wc
            ]
        )
        field = cond.args[0].field

        # or-in condition
        if isinstance(cond, ConditionOR):
            # contains-any
            if test_val.startswith(self.wildcard_single) and test_val.endswith(
                self.wildcard_single
            ):
                result = self.icontains_any_expression.format(
                    field=field, list=vals_formatted
                )
            # startswith-any
            elif test_val.endswith(self.wildcard_single) and not test_val.startswith(
                self.wildcard_single
            ):
                result = self.istartswith_any_expression.format(
                    field=field, list=vals_formatted
                )
            # endswith-any
            elif test_val.startswith(self.wildcard_single) and not test_val.endswith(
                self.wildcard_single
            ):
                escaped_vals = [
                    re.escape(val).replace("/", "\\/") for val in vals_no_wc
                ]
                exp = "(.*{}$)".format("$|.*".join(escaped_vals))
                result = self.re_expression.format(field=field, regex=exp)
            # iin
            else:
                result = self.field_in_list_expression.format(
                    field=field, list=vals_formatted
                )
        # contains-all
        else:
            result = self.icontains_all_expression.format(
                field=field, list=vals_formatted
            )

        return result

    # finalize query for use with log search 'Advanced' option
    def finalize_query_leql_advanced_search(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return f"""where({query})"""

    # finalize query the way it appears under Detection Rules -> Attacker Behavior Analytics -> Rule Logic
    def finalize_query_leql_detection_definition(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        entry_type = rule.logsource.category
        formatted_query = "\n  ".join(re.split("(AND |OR )", query))
        return f"""from(
  entry_type = "{entry_type}"
)
where(
  {formatted_query}
)"""

    def finalize_output_leql_advanced_search(self, queries: List[str]) -> List[str]:
        return self.finalize_output_default(queries)

    def finalize_output_leql_detection_definition(
        self, queries: List[str]
    ) -> List[str]:
        return self.finalize_output_default(queries)
