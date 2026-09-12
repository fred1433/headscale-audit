"""HuJSON, the two JSON dialects headscale speaks, and the read-only contract."""

from __future__ import annotations

import inspect
import json
import os
import stat

import pytest

from headscale_audit import hujson, loaders
from headscale_audit.engine import run
from headscale_audit.loaders import HeadscaleAPI, parse_time
from headscale_audit.model import Inventory


class TestHuJSON:
    def test_line_and_block_comments_and_trailing_commas(self) -> None:
        document = """
        // leading comment
        {
          /* block
             comment */
          "groups": {"group:ops": ["ops@"],},
          "hosts": {"office": "192.0.2.0/24"}, // trailing
        }
        """
        assert hujson.loads(document) == {
            "groups": {"group:ops": ["ops@"]},
            "hosts": {"office": "192.0.2.0/24"},
        }

    def test_a_comment_marker_inside_a_string_survives(self) -> None:
        parsed = hujson.loads('{"note": "https://example.com/a//b", "x": 1,}')
        assert parsed["note"] == "https://example.com/a//b"

    def test_escaped_quote_inside_a_string(self) -> None:
        assert hujson.loads(r'{"a": "say \"hi\" // not a comment"}')["a"].endswith(
            "// not a comment"
        )

    @pytest.mark.parametrize("bad", ["", "// only a comment", "{", '{"a": /* }'])
    def test_invalid_documents_raise(self, bad: str) -> None:
        with pytest.raises(hujson.HuJSONError):
            hujson.loads(bad)


class TestNormalisation:
    def test_cli_and_api_shapes_agree(self, tmp_path) -> None:
        cli = [
            {
                "id": 1,
                "given_name": "gce-web-01",
                "last_seen": {"seconds": 1788611200, "nanos": 0},
                "approved_routes": ["10.0.0.0/8"],
                "pre_auth_key": {"acl_tags": ["tag:web"]},
            }
        ]
        api = {
            "nodes": [
                {
                    "id": "1",
                    "givenName": "gce-web-01",
                    "lastSeen": "2026-09-05T12:26:40Z",
                    "approvedRoutes": ["10.0.0.0/8"],
                    "preAuthKey": {"aclTags": ["tag:web"]},
                }
            ]
        }
        from_cli = loaders._as_list(cli, "nodes")[0]
        from_api = loaders._as_list(api, "nodes")[0]
        assert set(from_cli) == set(from_api)
        assert from_cli["given_name"] == from_api["given_name"]
        assert from_cli["pre_auth_key"]["acl_tags"] == ["tag:web"]
        assert parse_time(from_cli["last_seen"]) == parse_time(from_api["last_seen"])

    @pytest.mark.parametrize(
        "value",
        [None, "", {}, {"seconds": 0}, "0001-01-01T00:00:00Z", "not a date"],
    )
    def test_absent_timestamps_read_as_none(self, value) -> None:
        assert parse_time(value) is None

    def test_preauthkey_list_keys_of_both_dialects(self) -> None:
        cli = {"pre_auth_keys": [{"id": 1}]}
        api = {"preAuthKeys": [{"id": "1"}]}
        assert loaders._as_list(cli, "preauthkeys")[0]["id"] == 1
        assert loaders._as_list(api, "preauthkeys")[0]["id"] == "1"


class TestReadOnlyContract:
    def test_the_api_client_can_only_get(self) -> None:
        source = inspect.getsource(HeadscaleAPI)
        assert 'method="GET"' in source
        for forbidden in ("POST", "PUT", "DELETE", "PATCH"):
            assert forbidden not in source

    def test_no_module_writes_to_the_api(self) -> None:
        import pathlib

        root = pathlib.Path(loaders.__file__).parent
        for path in root.rglob("*.py"):
            text = path.read_text()
            assert "urlopen" not in text or path.name == "loaders.py"
            assert 'method="POST"' not in text


class TestFilePermissions:
    def test_group_readable_key_is_reported(self, tmp_path) -> None:
        key = tmp_path / "noise_private.key"
        key.write_text("privkey:redacted")
        os.chmod(key, 0o644)
        database = tmp_path / "db.sqlite"
        database.write_text("")
        os.chmod(database, 0o600)
        inventory = Inventory(
            config={
                "noise": {"private_key_path": str(key)},
                "database": {"sqlite": {"path": str(database)}},
            },
            config_path=str(tmp_path / "config.yaml"),
        )
        results = {result.check.id: result for result in run(inventory)}
        assert results["HS-008"].status == "fail"
        evidence = results["HS-008"].findings[0].evidence
        assert "0644" in evidence and str(key) in evidence

        os.chmod(key, 0o600)
        results = {result.check.id: result for result in run(inventory)}
        assert results["HS-008"].status == "pass"

    def test_paths_that_do_not_exist_are_not_a_pass(self) -> None:
        inventory = Inventory(
            config={"noise": {"private_key_path": "/var/lib/headscale/noise.key"}}
        )
        results = {result.check.id: result for result in run(inventory)}
        assert results["HS-008"].status == "not_evaluated"
        assert "host" in results["HS-008"].reason


class TestRelativePaths:
    def test_a_relative_key_path_resolves_next_to_the_config(self, tmp_path) -> None:
        key = tmp_path / "noise.key"
        key.write_text("x")
        os.chmod(key, 0o666)
        config = tmp_path / "config.yaml"
        config.write_text(json.dumps({"noise": {"private_key_path": "noise.key"}}))
        inventory = Inventory(
            config={"noise": {"private_key_path": "noise.key"}},
            config_path=str(config),
        )
        results = {result.check.id: result for result in run(inventory)}
        assert results["HS-008"].status == "fail"
        assert stat.S_IMODE(os.stat(key).st_mode) == 0o666
