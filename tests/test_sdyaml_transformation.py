from unittest import mock

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
        assert "Reference" not in res[0]

        rule.references = references
        res = transformation.apply(pipeline, rule, "query")
        assert res[0]["Reference"] == references[0]  # only first reference should be used

    def test_apply_author(self, pipeline, sigma_detection):
        author = "Cool Person"
        description = "description"

        transformation = SdYamlTransformation()
        rule = SigmaRule(
            "title",
            SigmaLogSource(product="windows"),
            sigma_detection,
            description=description,
        )
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] == description

        rule.author = author
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] == f"{description}\n\nAuthor: {author}"

    def test_apply_status(self, pipeline, rule):
        rule.description = "Some description"
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] == "Some description"

        rule.status = SigmaStatus.EXPERIMENTAL
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] == "Some description\n\nStatus: experimental"

    def test_apply_severity(self, pipeline, rule):
        severity = SigmaLevel.CRITICAL
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert "Severity" not in res[0]

        rule.level = severity
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Severity"] == "Critical"

    def test_apply_log_types(self, pipeline, rule):
        transformation = SdYamlTransformation()
        rule.logsource = SigmaLogSource(product="unknown")
        res = transformation.apply(pipeline, rule, "")
        assert "LogTypes" not in res[0]

        rule.logsource = SigmaLogSource(product="okta", service="okta")
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["LogTypes"] == ["Okta.SystemLog"]

        rule.logsource = SigmaLogSource(product="aws", service="cloudtrail")
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["LogTypes"] == ["AWS.CloudTrail"]

        with mock.patch("click.get_current_context") as mock_get_current_context:
            rule.logsource = SigmaLogSource(product="product", service="service")
            mock_get_current_context.return_value.params = {"pipeline": ["crowdstrike_panther"]}
            res = transformation.apply(pipeline, rule, "")
            assert res[0]["LogTypes"] == ["Crowdstrike.FDREvent"]

    def test_apply_false_positives(self, pipeline, sigma_detection):
        transformation = SdYamlTransformation()
        rule = SigmaRule(
            "title",
            SigmaLogSource(product="windows"),
            sigma_detection,
            falsepositives=[],
        )
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] is None

        rule.falsepositives = ["fp1", "fp2"]
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] == "False Positives: fp1, fp2"

    def test_mittre_tags(self, pipeline, rule):
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert "Reports" not in res[0]

        rule.tags = [SigmaRuleTag("attack", "t1001"), SigmaRuleTag("dunno", "t1001")]
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Reports"] == {"MITRE ATT&CK": ["T1001"]}
