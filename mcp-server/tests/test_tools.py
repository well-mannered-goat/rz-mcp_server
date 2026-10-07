"""
Simulator / compile-and-sanity test suite for tools.py.

Goal: catch real bugs (broken imports, wrong paths, wrong argument
handling, logic errors) WITHOUT needing a live VM. Two layers:

  1. Local-only tools (file reads/writes, no SSH) are tested directly.
  2. VM-dependent tools (build_binary, test_binary, etc.) are tested
     against a FakeSSHClient that mimics paramiko's interface, so we can
     simulate "the VM said X" without any real network connection.

Run with: pytest tests/test_tools.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tools  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture: redirect all of tools.py's module-level paths into a temp dir,
# so tests never touch the real project's data/tests/reports/etc.
# ---------------------------------------------------------------------------


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(tools, "VM_CONNECTION_INFO_PATH", tmp_path / "data" / "vm_connection.json")
    monkeypatch.setattr(tools, "TESTS_DIR", tmp_path / "tests")
    monkeypatch.setattr(tools, "CAPABILITIES_PATH", tmp_path / "context" / "rizin-debugger-commands")
    monkeypatch.setattr(tools, "VM_CONFIG_PATH", tmp_path / "vm_config.json")
    monkeypatch.setattr(tools, "REPORT_PATH_DIR", tmp_path / "reports")

    source_root = tmp_path / "rizin"
    source_root.mkdir(parents=True)
    monkeypatch.setattr(tools, "ALLOWED_SOURCE_ROOT", source_root)

    monkeypatch.setattr(tools, "TEST_ID", 0)

    return tmp_path


# ---------------------------------------------------------------------------
# A fake SSH client simulating the VM, so build_binary/test_binary/etc. can
# be exercised with zero network access. Configure it with a dict of
# {command_substring: (exit_code, stdout_bytes, stderr_bytes)}.
# ---------------------------------------------------------------------------


class FakeStream:
    def __init__(self, data: bytes, exit_code: int):
        self._data = data
        self._exit_code = exit_code
        self.channel = self

    def read(self) -> bytes:
        return self._data

    def decode(self):
        return self._data

    def recv_exit_status(self) -> int:
        return self._exit_code


class FakeSFTPFile:
    def __init__(self, store: dict, path: str):
        self._store = store
        self._path = path
        self._buffer = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._store[self._path] = "".join(self._buffer)
        return False

    def write(self, content: str):
        self._buffer.append(content)


class FakeSFTP:
    def __init__(self, store: dict):
        self._store = store

    def file(self, path: str, mode: str):
        return FakeSFTPFile(self._store, path)

    def close(self):
        pass


class FakeSSHClient:
    """Mimics the subset of paramiko.SSHClient's interface tools.py uses."""

    def __init__(self, responses: dict[str, tuple[int, bytes, bytes]], default=(0, b"", b"")):
        self._responses = responses
        self._default = default
        self.uploaded_files: dict[str, str] = {}
        self.closed = False

    def open_sftp(self) -> FakeSFTP:
        return FakeSFTP(self.uploaded_files)

    def exec_command(self, command: str):
        for substring, (exit_code, out, err) in self._responses.items():
            if substring in command:
                return None, FakeStream(out, exit_code), FakeStream(err, exit_code)
        exit_code, out, err = self._default
        return None, FakeStream(out, exit_code), FakeStream(err, exit_code)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_vm(sandbox, monkeypatch):
    """Patch _connect_to_vm to hand out a configurable FakeSSHClient."""

    state = {"client": None}

    def _install(responses: dict, default=(0, b"", b"")):
        client = FakeSSHClient(responses, default)
        state["client"] = client
        monkeypatch.setattr(tools, "_connect_to_vm", lambda: client)
        return client

    state["install"] = _install
    return state


# ---------------------------------------------------------------------------
# Local-only tools
# ---------------------------------------------------------------------------


def test_discover_capabilities_fallback(sandbox):
    result = tools.discover_capabilities()
    assert "db[?]" in result


def test_discover_capabilities_reads_real_file(sandbox):
    tools.CAPABILITIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    tools.CAPABILITIES_PATH.write_text("custom reference content")
    assert tools.discover_capabilities() == "custom reference content"


def test_get_vm_environment_reads_config(sandbox):
    tools.VM_CONFIG_PATH.write_text(json.dumps({"os": "debian", "arch": "x86_64"}))
    result = tools.get_vm_environment()
    assert "debian" in result


def test_get_vm_environment_missing_file_raises(sandbox):
    with pytest.raises(FileNotFoundError):
        tools.get_vm_environment()


def test_create_test_json_returns_id_and_persists(sandbox):
    test_id = tools.create_test_json(["db @ main"], "sanity check")
    assert isinstance(test_id, int)
    assert tools._test_record_path(test_id).is_file()

    stored = json.loads(tools._test_record_path(test_id).read_text())
    assert stored["commands"] == ["db @ main"]
    assert stored["description"] == "sanity check"
    assert stored["binary_path"] is None


def test_create_test_json_ids_increment(sandbox):
    first = tools.create_test_json(["a"], "first")
    second = tools.create_test_json(["b"], "second")
    assert second != first


def test_update_test_commands_overwrites(sandbox):
    test_id = tools.create_test_json(["old"], "desc")
    tools.update_test_commands(test_id, ["new", "commands"])
    stored = json.loads(tools._test_record_path(test_id).read_text())
    assert stored["commands"] == ["new", "commands"]


def test_read_source_file_valid_path(sandbox):
    (tools.ALLOWED_SOURCE_ROOT / "sub").mkdir()
    (tools.ALLOWED_SOURCE_ROOT / "sub" / "file.c").write_text("line1\nline2\nline3\n")

    result = tools.read_source_file("sub/file.c")
    assert "line1" in result and "line2" in result and "line3" in result


def test_read_source_file_line_range(sandbox):
    (tools.ALLOWED_SOURCE_ROOT / "file.c").write_text("a\nb\nc\nd\n")
    result = tools.read_source_file("file.c", line_range="2-3")
    assert "2: b" in result
    assert "3: c" in result
    assert "1: a" not in result


def test_read_source_file_rejects_path_traversal(sandbox):
    secret = sandbox / "secret.txt"
    secret.write_text("should never be readable")

    result = tools.read_source_file("../secret.txt")
    assert "outside the allowed Rizin source tree" in result


def test_read_source_file_rejects_absolute_path(sandbox):
    secret = sandbox / "secret.txt"
    secret.write_text("should never be readable")

    result = tools.read_source_file(str(secret))
    assert "outside the allowed Rizin source tree" in result


def test_read_source_file_missing_file(sandbox):
    result = tools.read_source_file("does_not_exist.c")
    assert "not found" in result


def test_search_rizin_source_finds_match(sandbox):
    (tools.ALLOWED_SOURCE_ROOT / "cmd_debug.c").write_text("void cmd_db(void) {}\n")
    result = tools.search_rizin_source("cmd_db")
    assert "cmd_debug.c" in result


def test_search_rizin_source_no_match(sandbox):
    (tools.ALLOWED_SOURCE_ROOT / "file.c").write_text("nothing relevant here\n")
    result = tools.search_rizin_source("totally_absent_symbol")
    assert "No matches found" in result


def test_get_rizin_source_path_exists(sandbox):
    result = tools.get_rizin_source_path()
    assert result == str(tools.ALLOWED_SOURCE_ROOT)


def test_create_report_default_template(sandbox):
    result = tools.create_report("something was found", "")
    assert "something was found" in result


def test_create_report_rejects_template_without_placeholder(sandbox):
    result = tools.create_report("findings", "no placeholder here")
    assert "must contain" in result


def test_submit_report_writes_file(sandbox):
    result = tools.submit_report("# Final Report\nAll good.", 0)
    report_path = tools.REPORT_PATH_DIR / f"report_test_0.md"
    assert report_path.is_file()
    assert "Final Report" in report_path.read_text()
    assert str(report_path) in result


# ---------------------------------------------------------------------------
# VM-dependent tools, exercised against FakeSSHClient
# ---------------------------------------------------------------------------


def test_build_binary_success(fake_vm):
    fake_vm["install"]({"gcc": (0, b"", b"")})
    test_id = tools.create_test_json(["db @ main"], "desc")

    result = tools.build_binary(test_id, "int main(){return 0;}")

    assert "Compiled successfully" in result
    stored = json.loads(tools._test_record_path(test_id).read_text())
    assert stored["binary_path"] == f"/tmp/{test_id}_binary"

    client = fake_vm["client"]
    assert client.closed is True
    assert f"/tmp/{test_id}_code.c" in client.uploaded_files
    assert "int main" in client.uploaded_files[f"/tmp/{test_id}_code.c"]


def test_build_binary_failure_sets_binary_path_none(fake_vm):
    fake_vm["install"]({"gcc": (1, b"", b"error: syntax error")})
    test_id = tools.create_test_json(["db @ main"], "desc")

    result = tools.build_binary(test_id, "not valid c code")

    assert "Compilation failed" in result
    stored = json.loads(tools._test_record_path(test_id).read_text())
    assert stored["binary_path"] is None


def test_test_binary_reports_exit_code_and_output(fake_vm):
    fake_vm["install"]({"chmod": (0, b"hello from binary\n", b"")})
    test_id = tools.create_test_json(["db @ main"], "desc")
    tools.build_binary(test_id, "int main(){return 0;}")

    result = tools.test_binary(test_id)
    assert "exit_code: 0" in result
    assert "hello from binary" in result


def test_run_test_uses_stored_commands(fake_vm):
    client = fake_vm["install"]({"rizin": (0, b"debugger output here", b"")})
    test_id = tools.create_test_json(["db @ main", "dc"], "desc")

    result = tools.run_test(test_id)

    assert "debugger output here" in result
    assert "exit_code: 0" in result


def test_run_test_no_commands_returns_message(fake_vm):
    fake_vm["install"]({})
    test_id = tools.create_test_json([], "desc")
    result = tools.run_test(test_id)
    assert "has no Rizin commands" in result


def test_get_binary_context_success(fake_vm):
    fake_vm["install"]({"rizin": (0, b"[Sections]\n.text\n", b"")})
    test_id = tools.create_test_json([], "desc")
    tools.build_binary(test_id, "int main(){return 0;}")

    result = tools.get_binary_context(test_id)
    assert ".text" in result


def test_get_binary_context_failure(fake_vm):
    fake_vm["install"]({"rizin": (1, b"", b"analysis failed")})
    test_id = tools.create_test_json([], "desc")

    result = tools.get_binary_context(test_id)
    assert "Rizin context collection failed" in result