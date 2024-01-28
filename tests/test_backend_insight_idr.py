import pytest
from sigma.collection import SigmaCollection
from sigma.backends.insight_idr import InsightIDRBackend


@pytest.fixture
def insight_idr_backend():
    return InsightIDRBackend()


def test_insight_idr_simple_eq_nocase_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: foo
                    condition: selection
            """
            )
        )
        == ['field = NOCASE("foo")']
    )


def test_insight_idr_single_quote(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: fo"o
                    condition: selection
            """
            )
        )
        == ["field = NOCASE('fo\"o')"]
    )


def test_insight_idr_triple_quote(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: fo'"o
                    condition: selection
            """
            )
        )
        == ['field = NOCASE("""fo\'"o""")']
    )


def test_insight_idr_leql_advanced_search_output_format(
    insight_idr_backend: InsightIDRBackend,
):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: foo
                    condition: selection
            """
            ),
            output_format="leql_advanced_search",
        )
        == ['where(field = NOCASE("foo"))']
    )


def test_insight_idr_leql_detection_definition_output_format(
    insight_idr_backend: InsightIDRBackend,
):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: foo
                    condition: selection
            """
            ),
            output_format="leql_detection_definition",
        )
        == [
            """from(
  entry_type = "process_start_event"
)
where(
  field = NOCASE("foo")
)"""
        ]
    )


def test_insight_idr_not_condition_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: foo
                    filter:
                        field: blah
                    condition: selection and not filter
            """
            )
        )
        == ['field = NOCASE("foo") AND NOT field = NOCASE("blah")']
    )


def test_insight_idr_simple_contains_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains: foo
                    condition: selection
            """
            )
        )
        == ['field ICONTAINS "foo"']
    )


def test_insight_idr_simple_startswith_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|startswith: foo
                    condition: selection
            """
            )
        )
        == ['field ISTARTS-WITH "foo"']
    )


def test_insight_idr_simple_endswith_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|endswith: foo
                    condition: selection
            """
            )
        )
        == ["field=/.*foo$/i"]
    )


def test_insight_idr_value_in_list_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
            )
        )
        == ['field IIN ["val1", "val2", "val3"]']
    )


def test_insight_idr_value_eq_or_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field1: val1
                    selection2:
                        field2: val2
                    condition: selection or selection2
            """
            )
        )
        == ['field1 = NOCASE("val1") OR field2 = NOCASE("val2")']
    )


def test_insight_idr_keyword_or_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        - val1
                        - val2
                    condition: selection
            """
            )
        )
        == ['"val1" OR "val2"']
    )


def test_insight_idr_keyword_and_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection1:
                        - val1
                    selection2:
                        - val2
                    condition: selection1 and selection2
            """
            )
        )
        == ['"val1" AND "val2"']
    )


def test_insight_idr_value_eq_and_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: val1
                    selection2:
                        field2: val2
                    condition: selection and selection2
            """
            )
        )
        == ['field = NOCASE("val1") AND field2 = NOCASE("val2")']
    )


def test_insight_idr_contains_any_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
            )
        )
        == ['field ICONTAINS-ANY ["val1", "val2", "val3"]']
    )


def test_insight_idr_contains_all_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains|all:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
            )
        )
        == ['field ICONTAINS-ALL ["val1", "val2", "val3"]']
    )


def test_insight_idr_startswith_any_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|startswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
            )
        )
        == ['field ISTARTS-WITH-ANY ["val1", "val2", "val3"]']
    )


def test_insight_idr_endswith_any_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|endswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """
            )
        )
        == ["field=/(.*val1$|.*val2$|.*val3$)/i"]
    )


def test_insight_idr_re_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|re: boo.*far
                    condition: selection
            """
            )
        )
        == ["field=/boo.*far/i"]
    )


def test_insight_idr_cidr_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|cidr: 192.168.0.0/16
                    condition: selection
            """
            )
        )
        == ["field = IP(192.168.0.0/16)"]
    )


def test_insight_idr_base64_query(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|base64: 'sigma rules!'
                    condition: selection
            """
            )
        )
        == ['field = NOCASE("c2lnbWEgcnVsZXMh")']
    )


def test_insight_idr_condition_nested_logic(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel1:
                        field|contains:
                            - val1
                            - val2
                    sel2a:
                        field|endswith:
                            - val3
                    sel2b:
                        field|contains:
                            - val4
                    condition: sel1 or (sel2a and sel2b)
            """
            )
        )
        == [
            'field ICONTAINS-ANY ["val1", "val2"] OR field=/.*val3$/i AND field ICONTAINS "val4"'
        ]
    )


def test_insight_idr_not_1_of_filter_condition(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains|all:
                            - val1
                            - val2
                    filter1:
                        field1|contains:
                            - val3
                    filter2:
                        field2|contains:
                            - val4
                    condition: selection and not 1 of filter*
            """
            )
        )
        == [
            'field ICONTAINS-ALL ["val1", "val2"] AND NOT (field1 ICONTAINS "val3" OR field2 ICONTAINS "val4")'
        ]
    )


def test_insight_idr_multi_selection_same_field(insight_idr_backend: InsightIDRBackend):
    assert (
        insight_idr_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection1:
                        field1: 'test'
                        field2|contains|all:
                            - val1
                            - val2
                    selection2:
                        field2|contains|all:
                            - val3
                            - val4
                    selection3:
                        field2|contains|all:
                            - val5
                            - val6
                    condition: selection1 and (selection2 or selection3)
            """
            )
        )
        == [
            'field1 = NOCASE("test") AND field2 ICONTAINS-ALL ["val1", "val2"] AND (field2 ICONTAINS-ALL ["val3", "val4"] OR field2 ICONTAINS-ALL ["val5", "val6"])'
        ]
    )
