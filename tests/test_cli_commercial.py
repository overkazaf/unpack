from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from unpack import __version__
from unpack.cli import EXIT_NOT_FOUND, EXIT_OK, app

runner = CliRunner()


def _make_mini_apk(path: Path, dex_bytes: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("lib/arm64-v8a/libjiagu.so", b"\x7fELF" + b"\x00" * 64)
    return path


class TestGlobalFlagsAndHelp:
    def test_version_flag(self):
        res = runner.invoke(app, ["--version"])
        assert res.exit_code == EXIT_OK
        assert __version__ in res.stdout

    def test_no_color_and_quiet_flags_work_and_do_not_leak(self):
        res = runner.invoke(app, ["--no-color", "--quiet"])
        assert res.exit_code == EXIT_OK
        # Subsequent call without flags must still render normal help
        res2 = runner.invoke(app, [])
        assert res2.exit_code == EXIT_OK
        assert "UNPACK" in res2.output
        assert "doctor" in res2.output
        assert "inspect" in res2.output
        assert "report" in res2.output


class TestDoctorCommand:
    def test_doctor_table_no_devices(self):
        res = runner.invoke(app, ["doctor", "--no-devices"])
        assert res.exit_code == EXIT_OK
        assert "UNPACK Doctor" in res.output
        assert "Environment Checks" in res.output

    def test_doctor_json_stdout(self):
        res = runner.invoke(app, ["doctor", "--no-devices", "--json", "-"])
        assert res.exit_code == EXIT_OK
        data = json.loads(res.stdout)
        assert "overall_status" in data
        assert "checks" in data
        assert "engines" in data
        assert isinstance(data["checks"], list)


class TestInspectCommand:
    def test_inspect_apk_table_and_json(self, synthetic_dex_bytes, tmp_path):
        apk = _make_mini_apk(tmp_path / "sample.apk", synthetic_dex_bytes)
        res = runner.invoke(app, ["inspect", str(apk)])
        assert res.exit_code == EXIT_OK
        assert "APK OVERVIEW" in res.output

        res_json = runner.invoke(app, ["inspect", str(apk), "--json", "-"])
        assert res_json.exit_code == EXIT_OK
        data = json.loads(res_json.stdout)
        assert data["file"] == "sample.apk"
        assert "sha256" in data

    def test_inspect_dex_table_and_json(self, tmp_dex):
        res = runner.invoke(app, ["inspect", str(tmp_dex), "--classes"])
        assert res.exit_code == EXIT_OK
        assert "DEX OVERVIEW" in res.output

        res_json = runner.invoke(app, ["inspect", str(tmp_dex), "--json", "-"])
        assert res_json.exit_code == EXIT_OK
        data = json.loads(res_json.stdout)
        assert "overview" in data

    def test_inspect_missing_json_error(self, tmp_path):
        res = runner.invoke(app, ["inspect", str(tmp_path / "missing.apk"), "--json", "-"])
        assert res.exit_code == EXIT_NOT_FOUND
        assert "error" in json.loads(res.stdout)


class TestReportCommand:
    def test_report_html_and_sarif_and_markdown_from_dex_dir(self, tmp_dex_dir, tmp_path):
        html_out = tmp_path / "audit.html"
        res_html = runner.invoke(app, ["report", str(tmp_dex_dir), "-F", "html", "-o", str(html_out)])
        assert res_html.exit_code == EXIT_OK
        html_text = html_out.read_text()
        assert html_text.startswith("<!DOCTYPE html>")

        res_sarif = runner.invoke(app, ["report", str(tmp_dex_dir), "-F", "sarif"])
        assert res_sarif.exit_code == EXIT_OK
        sarif = json.loads(res_sarif.stdout)
        assert sarif["version"] == "2.1.0"

        res_md = runner.invoke(app, ["report", str(tmp_dex_dir), "-F", "markdown"])
        assert res_md.exit_code == EXIT_OK
        assert "# UNPACK Audit Report" in res_md.stdout

    def test_report_on_apk_with_json(self, synthetic_dex_bytes, tmp_path):
        apk = _make_mini_apk(tmp_path / "packed.apk", synthetic_dex_bytes)
        res = runner.invoke(app, ["report", str(apk), "-F", "json"])
        assert res.exit_code == EXIT_OK
        data = json.loads(res.stdout)
        assert data["target"] == "packed.apk"
        assert data["scan"] is not None

    def test_report_missing_target(self, tmp_path):
        res = runner.invoke(app, ["report", str(tmp_path / "nope"), "-F", "json"])
        assert res.exit_code == EXIT_NOT_FOUND
        assert "error" in json.loads(res.stdout)


class TestPipePurityAndFormats:
    def test_vmp_json_stdout_is_pure_json(self, tmp_dex_dir):
        """Regression test: `vmp --json -` used to print Rich panels before JSON."""
        res = runner.invoke(app, ["vmp", str(tmp_dex_dir), "--json", "-"])
        assert res.exit_code == EXIT_OK
        data = json.loads(res.stdout)
        assert set(data.keys()) == {
            "total_methods",
            "normal_count",
            "nop_count",
            "vmp_count",
            "vmp_methods",
            "call_graph",
        }

    def test_scan_sarif_and_html_formats(self, synthetic_dex_bytes, tmp_path):
        apk = _make_mini_apk(tmp_path / "packed.apk", synthetic_dex_bytes)
        res_sarif = runner.invoke(app, ["scan", str(apk), "-F", "sarif"])
        assert res_sarif.exit_code == EXIT_OK
        sarif = json.loads(res_sarif.stdout)
        assert sarif["version"] == "2.1.0"

        html_path = tmp_path / "scan.html"
        res_html = runner.invoke(app, ["scan", str(apk), "-F", "html", "-o", str(html_path)])
        assert res_html.exit_code == EXIT_OK
        assert html_path.read_text().startswith("<!DOCTYPE html>")

    def test_verify_sarif_format(self, tmp_dex):
        res = runner.invoke(app, ["verify", str(tmp_dex), "-F", "sarif"])
        assert res.exit_code == EXIT_OK
        sarif = json.loads(res.stdout)
        assert sarif["version"] == "2.1.0"

    def test_export_and_reassemble_json_stdout(self, synthetic_dex_bytes, tmp_path):
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes.dex").write_bytes(synthetic_dex_bytes)
        apk = _make_mini_apk(tmp_path / "app.apk", synthetic_dex_bytes)

        res_exp = runner.invoke(app, ["export", str(dex_dir), "-o", str(tmp_path / "fart"), "-j", "-"])
        assert res_exp.exit_code == EXIT_OK
        assert json.loads(res_exp.stdout)["format"] == "fart"

        res_re = runner.invoke(app, ["reassemble", str(apk), str(dex_dir), "-j", "-"])
        assert res_re.exit_code == EXIT_OK
        assert "classes_mapped" in json.loads(res_re.stdout)

    def test_dump_phase_numbering_and_report_html(self, synthetic_dex_bytes, tmp_path, monkeypatch):
        apk = _make_mini_apk(tmp_path / "app.apk", synthetic_dex_bytes)
        out_dir = tmp_path / "unpacked"
        html_path = tmp_path / "dump_audit.html"

        def _fake_dispatch(self, apk, scan_result, output_dir, **kwargs):
            dex_file = output_dir / "classes_000.dex"
            dex_file.write_bytes(synthetic_dex_bytes)
            return SimpleNamespace(dex_files=[dex_file], duration_ms=120, error=None)

        monkeypatch.setattr("unpack.core.dispatcher.Dispatcher.dispatch", _fake_dispatch)

        res = runner.invoke(
            app,
            ["dump", str(apk), "-o", str(out_dir), "--report-html", str(html_path)],
        )
        assert res.exit_code == EXIT_OK
        assert "Step 1/4" in res.output
        assert "Step 4/4" in res.output
        assert (out_dir / "report.json").exists()
        assert html_path.exists()
        assert html_path.read_text().startswith("<!DOCTYPE html>")
