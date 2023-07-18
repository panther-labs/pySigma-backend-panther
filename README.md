# pySigma panther_sdyaml Backend

![Tests](https://github.com/josh-panther/pySigma-backend-panther-wip/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

This is the panther_python backend for pySigma. It provides the package `sigma.backends.panther` with the `PantherSdYamlBackend` class.

It supports the following output formats:

* default: Panther SDYAML "Simple Detections" .yaml format

Further, it contains the following processing pipelines in `sigma.pipelines.panther_sdyaml`:

* panther_sdyaml_pipeline: Convert known Sigma field names into their Panther schema equivalent

This backend is currently maintained by:

* [Josh Esbrook](https://github.com/josh-panther/)