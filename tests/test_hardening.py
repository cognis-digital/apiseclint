"""Tests for hardened error handling and edge cases in APISECLINT.

These tests cover graceful failure modes added during the hardening pass:
empty input, malformed JSON, non-dict roots, type errors, and webhook
edge cases.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apiseclint.core import load_spec, lint_spec
from apiseclint import cli


# ---------------------------------------------------------------------------
# load_spec edge cases
# ---------------------------------------------------------------------------

class TestLoadSpecHardening(unittest.TestCase):
    def test_empty_string_raises_value_error(self):
        """Empty input must raise ValueError with a clear message."""
        with self.assertRaises(ValueError) as ctx:
            load_spec("")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_whitespace_only_raises_value_error(self):
        """Whitespace-only input must raise ValueError."""
        with self.assertRaises(ValueError):
            load_spec("   \n\t  ")

    def test_non_str_raises_type_error(self):
        """Non-string input must raise TypeError, not AttributeError."""
        with self.assertRaises(TypeError):
            load_spec(None)  # type: ignore[arg-type]

    def test_json_array_raises_value_error(self):
        """A valid JSON array at the root is not a valid spec."""
        with self.assertRaises(ValueError) as ctx:
            load_spec("[1, 2, 3]")
        self.assertIn("mapping", str(ctx.exception).lower())

    def test_json_scalar_raises_value_error(self):
        """A bare JSON scalar (number) is not a valid spec."""
        with self.assertRaises(ValueError):
            load_spec("42")

    def test_malformed_json_raises_value_error(self):
        """Malformed JSON that also isn't YAML must raise, not silently return None."""
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            load_spec("{bad json:::")


# ---------------------------------------------------------------------------
# lint_spec type guard
# ---------------------------------------------------------------------------

class TestLintSpecHardening(unittest.TestCase):
    def test_non_dict_raises_type_error(self):
        """lint_spec must reject non-dict input with a clear TypeError."""
        with self.assertRaises(TypeError) as ctx:
            lint_spec("not a dict")  # type: ignore[arg-type]
        self.assertIn("dict", str(ctx.exception).lower())

    def test_list_input_raises_type_error(self):
        """lint_spec must reject a list with TypeError."""
        with self.assertRaises(TypeError):
            lint_spec([{"openapi": "3.0.0"}])  # type: ignore[arg-type]

    def test_empty_spec_dict_returns_report(self):
        """An empty dict spec is valid input — should produce findings, not crash."""
        rep = lint_spec({}, source="empty-dict")
        self.assertEqual(rep.source, "empty-dict")
        self.assertIsInstance(rep.findings, list)
        # Must fire AUTHN001 (no security schemes) at minimum
        ids = {f.rule_id for f in rep.findings}
        self.assertIn("AUTHN001", ids)

    def test_spec_with_none_paths_does_not_crash(self):
        """paths: null is valid YAML/JSON and must not crash the engine."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": None,
        }
        rep = lint_spec(spec, source="none-paths")
        self.assertIsInstance(rep.findings, list)

    def test_spec_with_none_servers_does_not_crash(self):
        """servers: null must not crash the TLS rule."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "servers": None,
            "paths": {},
        }
        rep = lint_spec(spec, source="none-servers")
        self.assertIsInstance(rep.findings, list)


# ---------------------------------------------------------------------------
# CLI edge cases
# ---------------------------------------------------------------------------

class TestCliHardening(unittest.TestCase):
    def _write_temp(self, content: str, suffix: str = ".json") -> str:
        fh = tempfile.NamedTemporaryFile(
            "w", suffix=suffix, delete=False, encoding="utf-8"
        )
        fh.write(content)
        fh.close()
        return fh.name

    def test_empty_file_returns_exit_2(self):
        """An empty spec file should produce exit code 2."""
        path = self._write_temp("")
        try:
            self.assertEqual(cli.main(["lint", path]), 2)
        finally:
            os.unlink(path)

    def test_malformed_json_returns_exit_2(self):
        """A JSON file with a syntax error should produce exit code 2."""
        path = self._write_temp("{invalid json!!}")
        try:
            self.assertEqual(cli.main(["lint", path]), 2)
        finally:
            os.unlink(path)

    def test_json_array_root_returns_exit_2(self):
        """A JSON file whose root is an array should produce exit code 2."""
        path = self._write_temp(json.dumps([1, 2, 3]))
        try:
            self.assertEqual(cli.main(["lint", path]), 2)
        finally:
            os.unlink(path)

    def test_clean_spec_returns_exit_0(self):
        """A spec with no security findings should exit 0."""
        clean = {
            "openapi": "3.0.3",
            "info": {"title": "Clean", "version": "1"},
            "servers": [{"url": "https://example.com"}],
            "security": [{"bearer": []}],
            "components": {
                "securitySchemes": {
                    "bearer": {"type": "http", "scheme": "bearer"}
                }
            },
            "paths": {
                "/items/{id}": {
                    "get": {
                        "security": [{"bearer": []}],
                        "parameters": [
                            {"name": "id", "in": "path", "required": True,
                             "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {"description": "ok"},
                            "401": {"description": "unauth"},
                            "429": {"description": "too many"},
                        },
                    }
                }
            },
        }
        path = self._write_temp(json.dumps(clean))
        try:
            self.assertEqual(cli.main(["lint", path]), 0)
        finally:
            os.unlink(path)

    def test_output_flag_writes_file(self):
        """The -o/--output flag should write the report to a file."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": {},
        }
        in_path = self._write_temp(json.dumps(spec))
        out_path = in_path + ".out.json"
        try:
            cli.main(["lint", in_path, "--format", "json", "-o", out_path])
            self.assertTrue(os.path.exists(out_path))
            with open(out_path, encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["tool"], "apiseclint")
        finally:
            os.unlink(in_path)
            if os.path.exists(out_path):
                os.unlink(out_path)


# ---------------------------------------------------------------------------
# mcp_server module compiles without errors
# ---------------------------------------------------------------------------

class TestMcpServerCompiles(unittest.TestCase):
    def test_module_imports_without_error(self):
        """mcp_server must import cleanly (MCP package is optional at runtime)."""
        import apiseclint.mcp_server as mod
        self.assertTrue(callable(mod.serve))


if __name__ == "__main__":
    unittest.main()
