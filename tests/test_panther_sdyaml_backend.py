import pytest
from sigma.collection import SigmaCollection
from sigma.backends.panther_python import PantherPythonBackend

@pytest.fixture
def panther_python_backend():
    return PantherPythonBackend()

def test_and_expression(panther_python_backend : PantherPythonBackend):
    assert panther_python_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ["""Detection:
    - Key: fieldA
      Condition: Equals
      Value: 'valueA'
    - Key: fieldB
      Condition: Equals
      Value: 'ValueB'
      """]
#
# def test_panther_python_or_expression(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel1:
#                     fieldA: valueA
#                 sel2:
#                     fieldB: valueB
#                 condition: 1 of sel*
#         """)
#     ) == ['event.get("fieldA") == "valueA" or event.get("fieldB") == "valueB"']
#
# def test_panther_python_and_or_expression(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA1
#                         - valueA2
#                     fieldB:
#                         - valueB1
#                         - valueB2
#                 condition: sel
#         """)
#     ) == ['(event.get("fieldA") in ["valueA1", "valueA2"]) and (event.get("fieldB") in ["valueB1", "valueB2"])']
#
# def test_panther_python_or_and_expression(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel1:
#                     fieldA: valueA1
#                     fieldB: valueB1
#                 sel2:
#                     fieldA: valueA2
#                     fieldB: valueB2
#                 condition: 1 of sel*
#         """)
#     ) == ['(event.get("fieldA") == "valueA1" and event.get("fieldB") == "valueB1") or (event.get("fieldA") == "valueA2" and event.get("fieldB") == "valueB2")']
#
# def test_panther_python_in_expression(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA
#                         - valueB
#                         - valueC
#                 condition: sel
#         """)
#     ) == ['event.get("fieldA") in ["valueA", "valueB", "valueC"]']
#
# def test_panther_python_in_expression_with_wildcard_startswith(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA
#                         - valueB
#                         - valueC*
#                 condition: sel
#         """)
#     ) == ['event.get("fieldA") == "valueA" or event.get("fieldA") == "valueB" or event.get("fieldA").startswith("valueC")']
#
# def test_panther_python_in_expression_with_wildcard_endswith(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA
#                         - valueB
#                         - "*valueC"
#                 condition: sel
#         """)
#     ) == ['event.get("fieldA") == "valueA" or event.get("fieldA") == "valueB" or event.get("fieldA").endswith("valueC")']
#
# def test_panther_python_in_expression_with_wildcard_contains(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA
#                         - valueB
#                         - "*valueC*"
#                 condition: sel
#         """)
#     ) == ['event.get("fieldA") == "valueA" or event.get("fieldA") == "valueB" or "valueC" in event.get("fieldA")']
#
# def test_panther_python_regex_query(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA|re: foo.*bar
#                     fieldB: foo
#                 condition: sel
#         """)
#     ) == ['re.compile(r"foo.*bar").search(event.get("fieldA")) and event.get("fieldB") == "foo"']
#
# def test_panther_python_cidr_query(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA|cidr: 192.168.0.0/16
#                 condition: sel
#         """)
#     ) == ['ipaddress.ip_address(event.get("fieldA")) in ipaddress.ip_network("192.168.0.0/16")']
#
# def test_panther_python_field_name_with_whitespace(panther_python_backend : PantherPythonBackend):
#     assert panther_python_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field name: value
#                 condition: sel
#         """)
#     ) == ['event.get("field name") == "value"']

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
#   implemented with custom code, deferred expressions etc.

