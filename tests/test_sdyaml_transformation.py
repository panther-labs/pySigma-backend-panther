from sigma.rule import SigmaRule, SigmaLogSource, SigmaLevel

from sigma.pipelines.panther.sdyaml_transformation import SdYamlTransformation


class TestSdYamlTransformation:

    def test_apply_reference(self, pipeline, rule):
        transformation = SdYamlTransformation()
        references = ["https://example.com/", "https://example2.com/", "https://example3.com/"]

        res = transformation.apply(pipeline, rule, "query")
        assert "Reference" not in res[0]

        rule.references = references
        res = transformation.apply(pipeline, rule, "query")
        assert res[0]["Reference"] == references[0] + ", " + references[1] + ", " + references[2]

    def test_apply_author(self, pipeline, sigma_detection):
        author = "Cool Person"
        description = "description"

        transformation = SdYamlTransformation()
        rule = SigmaRule("title", SigmaLogSource(product="windows"), sigma_detection, description=description)
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] == description

        rule.author = author
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Description"] == f"{description}\n\nAuthor: {author}"

    def test_apply_severity(self, pipeline, rule):
        severity = SigmaLevel.CRITICAL
        transformation = SdYamlTransformation()
        res = transformation.apply(pipeline, rule, "")
        assert "Severity" not in res[0]

        rule.level = severity
        res = transformation.apply(pipeline, rule, "")
        assert res[0]["Severity"] == severity.name
