"""Smoke tests for APISECLINT. No network. Run: python -m pytest (or unittest)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apiseclint import (  # noqa: E402
    lint_spec, load_spec, render_table, render_json, render_html,
    TOOL_NAME, TOOL_VERSION,
)
from apiseclint.core import Severity  # noqa: E402
from apiseclint import cli  # noqa: E402


INSECURE = {
    "openapi": "3.0.3",
    "info": {"title": "T", "version": "1"},
    "servers": [{"url": "http://x.example.com"}],
    "components": {
        "securitySchemes": {
            "b": {"type": "http", "scheme": "basic"},
            "k": {"type": "apiKey", "in": "query", "name": "api_key"},
        },
        "schemas": {
            "U": {"type": "object", "properties": {
                "id": {"type": "integer"}, "password": {"type": "string"}}},
        },
    },
    "paths": {
        "/pets": {
            "get": {"security": [], "responses": {"200": {"description": "ok"}}},
            "post": {"requestBody": {"content": {"application/json": {
                "schema": {"type": "object", "properties": {"n": {"type": "string"}}}}}},
                "responses": {"201": {"description": "ok"}}},
        }
    },
}

SECURE = {
    "openapi": "3.0.3",
    "info": {"title": "Safe", "version": "2"},
    "servers": [{"url": "https://x.example.com"}],
    "security": [{"oidc": ["read"]}],
    "components": {"securitySchemes": {"oidc": {
        "type": "openIdConnect", "openIdConnectUrl": "https://x/.well-known"}}},
    "paths": {
        "/items/{id}": {
            "get": {
                "security": [{"oidc": ["read"]}],
                "responses": {
                    "200": {"description": "ok"},
                    "401": {"description": "unauth"},
                    "429": {"description": "too many"},
                },
            }
        }
    },
}


class TestEngine(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "apiseclint")
        self.assertTrue(TOOL_VERSION)

    def test_insecure_spec_has_findings_and_fails(self):
        rep = lint_spec(INSECURE, "mem")
        ids = {f.rule_id for f in rep.findings}
        for expected in ("TLS001", "AUTHZ001", "AUTHN003", "AUTHN004",
                         "DATA001", "MASS001", "RATE001"):
            self.assertIn(expected, ids, f"missing {expected}")
        self.assertTrue(rep.failed)

    def test_severity_present(self):
        rep = lint_spec(INSECURE, "mem")
        self.assertIn(Severity.HIGH, {f.severity for f in rep.findings})

    def test_secure_spec_minimal_findings(self):
        rep = lint_spec(SECURE, "mem")
        ids = {f.rule_id for f in rep.findings}
        for not_expected in ("TLS001", "AUTHN001", "AUTHZ001", "AUTHZ002",
                             "RATE001", "DOC001"):
            self.assertNotIn(not_expected, ids, f"unexpected {not_expected}")

    def test_writeonly_suppresses_data_finding(self):
        spec = {
            "openapi": "3.0.0", "info": {"title": "x", "version": "1"},
            "security": [{"k": []}],
            "components": {"securitySchemes": {"k": {"type": "http", "scheme": "bearer"}},
                "schemas": {"U": {"type": "object", "properties": {
                    "password": {"type": "string", "writeOnly": True}}}}},
            "paths": {},
        }
        rep = lint_spec(spec, "mem")
        self.assertNotIn("DATA001", {f.rule_id for f in rep.findings})

    def test_renderers(self):
        rep = lint_spec(INSECURE, "mem")
        self.assertIn("APISECLINT", render_table(rep))
        payload = json.loads(render_json(rep))
        self.assertEqual(payload["tool"], "apiseclint")
        self.assertTrue(payload["failed"])
        self.assertEqual(payload["total"], len(rep.findings))
        html = render_html(rep)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("APISECLINT report", html)
        self.assertIn("<style>", html)

    def test_html_escapes(self):
        spec = {"openapi": "3.0.0",
                "info": {"title": "<script>x</script>", "version": "1"},
                "paths": {}}
        html = render_html(lint_spec(spec, "mem"))
        self.assertNotIn("<script>x</script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestYamlLoader(unittest.TestCase):
    def test_min_yaml(self):
        text = (
            "openapi: 3.0.0\n"
            "info:\n"
            "  title: YamlApi\n"
            "  version: '1.0'\n"
            "paths:\n"
            "  /ping:\n"
            "    get:\n"
            "      responses:\n"
            "        '200':\n"
            "          description: ok\n"
        )
        spec = load_spec(text)
        self.assertEqual(spec["info"]["title"], "YamlApi")
        self.assertIn("/ping", spec["paths"])


class TestCli(unittest.TestCase):
    def test_lint_file_exit_code(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(INSECURE, fh)
            path = fh.name
        try:
            self.assertEqual(cli.main(["lint", path, "--format", "json"]), 1)
            self.assertEqual(cli.main(["lint", path, "--exit-zero"]), 0)
        finally:
            os.unlink(path)

    def test_missing_file(self):
        self.assertEqual(cli.main(["lint", "does-not-exist.json"]), 2)


if __name__ == "__main__":
    unittest.main()
