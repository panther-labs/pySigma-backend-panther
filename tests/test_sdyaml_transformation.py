from unittest import mock

import pytest
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
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
            logsource=SigmaLogSource(product="okta", service="okta"),
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

    def test_apply_log_types_no_logtype(self, pipeline, rule):
        transformation = SdYamlTransformation()
        rule.logsource = SigmaLogSource(product="unknown")
        with pytest.raises(SigmaFeatureNotSupportedByBackendError) as err:
            transformation.apply(pipeline, rule, "")
        assert err.value.args[0] == "Can't map any LogTypes"

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
            logsource=SigmaLogSource(product="okta", service="okta"),
            detection=sigma_detection,
            falsepositives=[],
        )
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] is None

        rule.falsepositives = ["fp1", "fp2"]
        res = transformation.apply(pipeline, rule, "")
        assert res["Description"] == "False Positives: fp1, fp2"

    @pytest.mark.parametrize(
        ("tag", "expected_result"),
        (
            ("initial-access", "TA0001"),
            ("execution", "TA0002"),
            ("persistence", "TA0003"),
            ("privilege-escalation", "TA0004"),
            ("defense-evasion", "TA0005"),
            ("credential-access", "TA0006"),
            ("discovery", "TA0007"),
            ("lateral-movement", "TA0008"),
            ("collection", "TA0009"),
            ("exfiltration", "TA0010"),
            ("command-and-control", "TA0011"),
            ("impact", "TA0040"),
            ("resource-development", "TA0042"),
            ("reconnaissance", "TA0043"),
        ),
    )
    def test_mitre_tags(self, pipeline, rule, tag, expected_result):
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert "Reports" not in res

        rule.tags = [SigmaRuleTag("attack", "t1001"), SigmaRuleTag("attack", tag)]
        res = transformation.apply(pipeline, rule, "")
        assert res["Reports"] == {"MITRE ATT&CK": [f"{expected_result}:T1001"]}

    def test_mitre_tags_unknown_tactic(self, pipeline, rule):
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert "Reports" not in res

        rule.tags = [SigmaRuleTag("attack", "t1001"), SigmaRuleTag("attack", "fake-tactic-name")]
        with pytest.raises(SigmaFeatureNotSupportedByBackendError) as err:
            transformation.apply(pipeline, rule, "")
        assert err.value.args[0] == "MITRE ATT&CK tactic fake-tactic-name not found recognized"

    def test_mitre_tags_no_tactic(self, pipeline, rule):
        transformation = SdYamlTransformation()
        rule.tags = [SigmaRuleTag("attack", "t1001")]
        with pytest.warns():
            res = transformation.apply(pipeline, rule, "")
        assert "Reports" not in res
