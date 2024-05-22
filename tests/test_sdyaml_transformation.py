from unittest import mock

import pytest
from sigma.rule import SigmaLevel, SigmaLogSource, SigmaRule, SigmaRuleTag, SigmaStatus

from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


class TestSdYamlTransformation:
    def test_apply_reference(self, pipeline, rule):
        transformation = SdYamlTransformation()
        references = [
            "https://example.com/",
            "https://example2.com/",
            "https://example3.com/",
        ]

        res = transformation.apply(pipeline, rule, "query")
        assert "Reference" not in res

        rule.references = references
        res = transformation.apply(pipeline, rule, "query")
        assert res["Reference"] == references[0]  # only first reference should be used

    def test_apply_author(self, pipeline, sigma_detection):
        author = "Cool Person"
        description = "description"

        transformation = SdYamlTransformation()
        rule = SigmaRule(
            "title",
            logsource=SigmaLogSource(product="windows"),
            detection=sigma_detection,
            description=description,
        )
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] == description

        rule.author = author
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] == f"{description}\n\nAuthor: {author}"

    def test_apply_status(self, pipeline, rule):
        rule.description = "Some description"
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] == "Some description"

        rule.status = SigmaStatus.EXPERIMENTAL
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] == "Some description\n\nStatus: experimental"

    def test_apply_severity(self, pipeline, rule):
        severity = SigmaLevel.CRITICAL
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert "Severity" not in res

        rule.level = severity
        res = transformation.apply(pipeline, rule, "")
        assert res["Severity"] == "Critical"

    @pytest.mark.parametrize(
        "sigma_log_source, expected_result",
        (
            (SigmaLogSource(product="unknown"), None),
            (SigmaLogSource(product="okta", service="okta"), ["Okta.SystemLog"]),
            (SigmaLogSource(product="aws", service="cloudtrail"), ["AWS.CloudTrail"]),
            (SigmaLogSource(product="github", service="audit"), ["GitHub.Audit"]),
        ),
    )
    def test_apply_log_types(self, expected_result, sigma_log_source, pipeline, rule):
        transformation = SdYamlTransformation()
        rule.logsource = sigma_log_source
        res = transformation.apply(pipeline, rule, "")
        assert res.get("LogTypes") == expected_result

    def test_apply_log_types_crowdstrike(self, pipeline, rule):
        transformation = SdYamlTransformation()

        with mock.patch("click.get_current_context") as mock_get_current_context:
            rule.logsource = SigmaLogSource(product="product", service="service")
            mock_get_current_context.return_value.params = {"pipeline": ["crowdstrike_panther"]}
            res = transformation.apply(pipeline, rule, "")
            assert res["LogTypes"] == ["Crowdstrike.FDREvent"]

    def test_apply_false_positives(self, pipeline, sigma_detection):
        transformation = SdYamlTransformation()
        rule = SigmaRule(
            "title",
            logsource=SigmaLogSource(product="windows"),
            detection=sigma_detection,
            falsepositives=[],
        )
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] is None

        rule.falsepositives = ["fp1", "fp2"]
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] == "False Positives: fp1, fp2"

    def test_mittre_tags(self, pipeline, rule):
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert "Reports" not in res

        rule.tags = [SigmaRuleTag("attack", "t1001"), SigmaRuleTag("dunno", "t1001")]
        res = transformation.apply(pipeline, rule, "")
        assert res["Reports"] == {"MITRE ATT&CK": ["T1001"]}
