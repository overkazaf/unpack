from __future__ import annotations

import json
import zipfile

from typer.testing import CliRunner

from unpack.cli import app

runner = CliRunner()


class TestVerifyJson:
    def test_verify_json_output(self, tmp_dex, tmp_path):
        out = tmp_path / "result.json"
        result = runner.invoke(app, ["verify", str(tmp_dex), "--json", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert data[0]["valid"] is True

    def test_verify_json_stdout(self, tmp_dex):
        result = runner.invoke(app, ["verify", str(tmp_dex), "--json", "-"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert data[0]["file"] == tmp_dex.name
        assert "issues" in data[0]
        assert "stats" in data[0]

    def test_verify_json_directory(self, tmp_dex_dir, tmp_path):
        out = tmp_path / "result.json"
        result = runner.invoke(app, ["verify", str(tmp_dex_dir), "--json", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert len(data) == 2

    def test_verify_json_missing_path_is_still_valid_json(self, tmp_path):
        result = runner.invoke(app, ["verify", str(tmp_path / "nope.dex"), "--json", "-"])
        assert result.exit_code != 0
        data = json.loads(result.stdout)
        assert "error" in data


class TestRepairJson:
    def test_repair_json_output(self, tmp_dex, tmp_path):
        out = tmp_path / "result.json"
        result = runner.invoke(app, ["repair", str(tmp_dex), "--json", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert data[0]["success"] is True

    def test_repair_json_stdout(self, tmp_dex):
        result = runner.invoke(app, ["repair", str(tmp_dex), "--json", "-"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert "actions" in data[0]
        assert "nop_methods" in data[0]

    def test_repair_json_missing_path_is_still_valid_json(self, tmp_path):
        result = runner.invoke(app, ["repair", str(tmp_path / "nope.dex"), "--json", "-"])
        assert result.exit_code != 0
        data = json.loads(result.stdout)
        assert "error" in data


class TestRepackJson:
    def _build_apk(self, path, dex_data: bytes = b"original"):
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("classes.dex", dex_data)
            zf.writestr("AndroidManifest.xml", b"manifest")

    def test_repack_json_output(self, synthetic_dex_bytes, tmp_path):
        apk = tmp_path / "test.apk"
        self._build_apk(apk)
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)

        out = tmp_path / "result.json"
        result = runner.invoke(
            app,
            ["repack", str(apk), str(dex_dir), "-o", str(tmp_path / "out"), "--json", str(out)],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["success"] is True
        assert data["dex_count"] == 1
        assert "resources" in data

    def test_repack_json_stdout(self, synthetic_dex_bytes, tmp_path):
        apk = tmp_path / "test.apk"
        self._build_apk(apk)
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)

        result = runner.invoke(
            app,
            ["repack", str(apk), str(dex_dir), "-o", str(tmp_path / "out"), "--json", "-"],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["success"] is True
        assert "output" in data

    def test_repack_json_missing_apk_is_still_valid_json(self, tmp_path):
        result = runner.invoke(
            app, ["repack", str(tmp_path / "nope.apk"), str(tmp_path), "--json", "-"]
        )
        assert result.exit_code != 0
        data = json.loads(result.stdout)
        assert "error" in data
