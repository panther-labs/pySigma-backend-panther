# pySigma Panther Backend

[![Test](https://github.com/panther-labs/pySigma-backend-panther/actions/workflows/test.yml/badge.svg)](https://github.com/panther-labs/pySigma-backend-panther/actions/workflows/test.yml)

Detailed docs about converting Sigma rules for Panther can be found [here](https://docs.panther.com/panther-developer-workflows/converting-sigma-rules).

This is the `panther` backend for pySigma. It provides the package `sigma.backends.panther` with the `PantherBackend` class.

It supports the following output formats:

- default: [Panther Python Detections](https://docs.panther.com/detections/rules/python) format
- sdyaml (`-f sdyaml`): [Panther YAML Detections](https://docs.panther.com/detections/rules/yaml#simple-detections)
  To save each rule in separate file you can use `output_dir` backend option.

```bash
sigma convert -t panther path/to/rules -p panther -O output_dir=output/directory
```

or

```bash
sigma convert -t panther -f sdyaml path/to/rules -p panther -O output_dir=output/directory
```

Further, it contains the following processing pipelines in `sigma.pipelines.panther`:

- panther_pipeline: Convert known Sigma field names into their Panther schema equivalent

## Local setup for development

The project is using [poetry](https://python-poetry.org/) for dependency management,
so after cloning it run: `poetry install` to install all the required dependencies.

Tests can be run with:

```bash
poetry run pytest
```

And rules can be converted with:

```bash
poetry run sigma convert -t panther -f sdyaml -p panther path_to_sigma_rule.yml`
```
