from mcp.server.fastmcp import FastMCP
from pathlib import Path
from typing import Optional
import json
import paramiko

mcp = FastMCP("debugger-triage")
TEST_ID = 0
VM_CONNECTION_INFO_PATH = Path("data/vm_connection.json")

ALLOWED_SOURCE_ROOT = Path("rizin").resolve()


def _connect_to_vm() -> paramiko.SSHClient:
    info = json.loads(VM_CONNECTION_INFO_PATH.read_text())

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=info["host"],
        port=info["port"],
        username=info["username"],
        password=info["password"],
    )

    return client


def _test_record_path(test_id: int) -> Path:
    return Path(f"tests/{test_id}.json")


def _load_test(test_id: int) -> dict:
    path = _test_record_path(test_id)

    if not path.is_file():
        raise FileNotFoundError(f"Test {test_id} does not exist")

    return json.loads(path.read_text())


def _resolve_within_source(path: str) -> Path | None:
    """Resolve `path` against ALLOWED_SOURCE_ROOT and refuse anything
    that escapes it, no matter how it's spelled (absolute paths, ../,
    symlinks). Returns None if the path is outside the allowed root."""
    candidate = (ALLOWED_SOURCE_ROOT / path).resolve()

    if candidate != ALLOWED_SOURCE_ROOT and ALLOWED_SOURCE_ROOT not in candidate.parents:
        return None

    return candidate


@mcp.tool()
def discover_capabilities() -> str:
    """Return the Rizin debugger's documented command reference so the agent knows which debugger commands are available."""
    capabilities_path = Path("context/rizin-debugger-commands")

    if capabilities_path.exists():
        return capabilities_path.read_text()

    return """\
db[?]           # Breakpoints commands
dc[?]           # Continue execution
dd[-lsdrw]      # Debug file descriptors commands
de[lcs?]        # Manage ESIL watchpoints
dg [<filename>] # Generate core dump file
do<rec>         # Debug (re)open commands
ds[?]           # Debug step commands
dt[?]           # Trace commands
di[jq]          # Debug information
dk[lnNo]        # Debug signals management
dl[l]           # Debug handler
dm[?]           # Memory map commands
dp[?]           # List or attach to process or thread
dr[?]           # CPU Registers
dw [<pid>]      # Block prompt until <pid> dies
dW[i]           # Windows process commands
dx[aers]        # Code injection commands
"""


@mcp.tool()
def get_vm_environment() -> str:
    """Return the VM's OS, architecture, compiler, and other environment information used to build and run the test."""
    return Path("./vm_config.json").read_text()


@mcp.tool()
def create_test_json(commands: list[str], test_description: str) -> int:
    """Create a new stored test with the intended Rizin commands and test description, and return its test ID."""
    global TEST_ID

    test_id = TEST_ID
    TEST_ID += 1

    Path("tests").mkdir(parents=True, exist_ok=True)

    test = {
        "commands": commands,
        "description": test_description,
        "test_id": test_id,
        "binary_path": None,
    }

    _test_record_path(test_id).write_text(json.dumps(test, indent=2))
    return test_id


@mcp.tool()
def build_binary(test_id: int, source_code: str) -> str:
    """Write the test source code to the VM, compile it there with GCC, and store the resulting remote binary path."""
    remote_source_path = f"/tmp/{test_id}_code.c"
    remote_binary_path = f"/tmp/{test_id}_binary"

    client = _connect_to_vm()

    try:
        sftp = client.open_sftp()

        with sftp.file(remote_source_path, "w") as remote_file:
            remote_file.write(source_code)

        sftp.close()

        command = f"gcc -fno-pie -no-pie -o {remote_binary_path} {remote_source_path}"
        _, stdout, stderr = client.exec_command(command)

        exit_code = stdout.channel.recv_exit_status()
        error_output = stderr.read().decode()

    finally:
        client.close()

    test_record_path = _test_record_path(test_id)
    test_record = _load_test(test_id)

    if exit_code != 0:
        test_record["binary_path"] = None
        test_record_path.write_text(json.dumps(test_record, indent=2))
        return f"Compilation failed:\n{error_output}"

    test_record["binary_path"] = remote_binary_path
    test_record_path.write_text(json.dumps(test_record, indent=2))

    return f"Compiled successfully: {remote_binary_path}"


@mcp.tool()
def test_binary(test_id: int) -> str:
    """Run the compiled test binary standalone on the VM and return its stdout, stderr, and exit code."""
    test_record = _load_test(test_id)
    remote_binary_path = test_record.get("binary_path") or f"/tmp/{test_id}_binary"

    client = _connect_to_vm()

    try:
        command = f"chmod +x {remote_binary_path} && {remote_binary_path}"
        _, stdout, stderr = client.exec_command(command)

        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode()
        error_output = stderr.read().decode()

    finally:
        client.close()

    return (
        f"exit_code: {exit_code}\n"
        f"stdout:\n{output}\n"
        f"stderr:\n{error_output}"
    )


@mcp.tool()
def get_binary_context(test_id: int) -> str:
    """Run Rizin's static analysis on the compiled binary and return architecture, entry point, functions, sections, symbols, and imports for constructing correct debugger commands."""
    test_record = _load_test(test_id)
    remote_binary_path = test_record.get("binary_path") or f"/tmp/{test_id}_binary"

    client = _connect_to_vm()

    try:
        command = f"rizin -q -c 'aaa;iI;ie;afl;iS;is;ii' {remote_binary_path}"
        _, stdout, stderr = client.exec_command(command)

        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode()
        error_output = stderr.read().decode()

    finally:
        client.close()

    if exit_code != 0:
        return f"Rizin context collection failed:\n{error_output}"

    return output


@mcp.tool()
def update_test_commands(test_id: int, new_commands: list[str]) -> str:
    """Replace the stored Rizin command sequence for a test with the agent's final commands."""
    test_record = _load_test(test_id)
    test_record["commands"] = new_commands

    _test_record_path(test_id).write_text(json.dumps(test_record, indent=2))

    return f"Updated commands for test {test_id}"


@mcp.tool()
def run_test(test_id: int) -> str:
    """Run the stored Rizin debugger commands against the test binary and return the debugger output, errors, and process exit code."""
    test_record = _load_test(test_id)
    remote_binary_path = test_record.get("binary_path") or f"/tmp/{test_id}_binary"
    commands = test_record.get("commands", [])

    if not commands:
        return f"Test {test_id} has no Rizin commands"

    if isinstance(commands, list):
        command_string = ";".join(commands)
    else:
        command_string = str(commands)

    client = _connect_to_vm()

    try:
        command = f"rizin -q -d -c '{command_string}' {remote_binary_path}"
        _, stdout, stderr = client.exec_command(command)

        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode()
        error_output = stderr.read().decode()

    finally:
        client.close()

    return (
        f"exit_code: {exit_code}\n"
        f"stdout:\n{output}\n"
        f"stderr:\n{error_output}"
    )


@mcp.tool()
def read_source_file(path: str, line_range: Optional[str] = None) -> str:
    """Read Rizin source code from a file inside the Rizin source tree, optionally restricted to a line range such as '120-150', so the agent can investigate command implementation errors. Paths outside the Rizin source tree are rejected."""
    resolved_path = _resolve_within_source(path)

    if resolved_path is None:
        return f"Path '{path}' is outside the allowed Rizin source tree and cannot be read."

    if not resolved_path.is_file():
        return f"Source file not found: {path}"

    lines = resolved_path.read_text().splitlines()

    if line_range is None:
        return "\n".join(lines)

    try:
        start, end = line_range.split("-", 1)
        start_line = int(start)
        end_line = int(end)

        if start_line < 1 or end_line < start_line:
            return f"Invalid line range: {line_range}"

        return "\n".join(
            f"{number}: {lines[number - 1]}"
            for number in range(start_line, min(end_line, len(lines)) + 1)
        )

    except ValueError:
        return f"Invalid line range: {line_range}. Expected format: 'start-end'."


@mcp.tool()
def create_report(findings: str, template: str) -> str:
    """Format the agent's findings into a deterministic Markdown report using the supplied template."""
    if not template.strip():
        template = """# Rizin Debugger Test Report

## Findings

{findings}
"""

    if "{findings}" not in template:
        return "Report template must contain a {findings} placeholder."

    return template.replace("{findings}", findings)


@mcp.tool()
def submit_report(report: str) -> str:
    """Save the final Markdown report to disk. This is the final tool in the test workflow."""
    report_path = Path("reports/report.md")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)

    return f"Report saved to {report_path}"

@mcp.tool()
def get_rizin_source_path() -> str:
    """Return the local path to the Rizin source tree so the agent can inspect Rizin's implementation."""
    source_path = Path("rizin")

    if not source_path.is_dir():
        return f"Rizin source directory not found: {source_path.resolve()}"

    return str(source_path.resolve())


@mcp.tool()
def search_rizin_source(query: str) -> str:
    """Search the Rizin source tree for a command, function, error message, or other text and return matching files and lines."""
    source_path = Path("rizin")

    if not source_path.is_dir():
        return f"Rizin source directory not found: {source_path.resolve()}"

    results = []

    for path in source_path.rglob("*"):
        if not path.is_file():
            continue

        if path.suffix not in {
            ".c", ".h", ".cc", ".cpp", ".hpp", ".rs",
            ".py", ".sh", ".md", ".txt"
        }:
            continue

        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue

        for line_number, line in enumerate(lines, start=1):
            if query.lower() in line.lower():
                results.append(
                    f"{path}:{line_number}: {line.strip()}"
                )

                if len(results) >= 100:
                    return "\n".join(results)

    if not results:
        return f"No matches found for: {query}"

    return "\n".join(results)

if __name__ == "__main__":
    mcp.run()