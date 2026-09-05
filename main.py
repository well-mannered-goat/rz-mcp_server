from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

PROFILE = {
    "distro": "debian",
    "arch": "x86_64",
    "version": "13.6.0",
    "kernel_version": "5.6.0-1",
    "username": "root",
}

VM_PORT = 2222

INSTALL_SCRIPT = Path("scripts/install.sh")
RUN_SCRIPT = Path("scripts/run.sh")
RECIPE_PATH = Path("prompts/investigate.yaml")
VM_CONNECTION_INFO_PATH = Path("data/vm_connection.json")

VM_READY_TIMEOUT_SECONDS = 120
VM_READY_POLL_INTERVAL_SECONDS = 2


def vm_image_path(profile: dict) -> Path:
    return Path(f"images/{profile['distro']}-{profile['version']}-{profile['arch']}-hdd.qcow2")


def run_shell_script(script_path: Path, *args: str) -> int:
    if not script_path.is_file():
        print(f"Script not found: {script_path}", file=sys.stderr)
        return 1

    result = subprocess.run(["bash", str(script_path), *args], check=False)
    return result.returncode


def ensure_vm_image(profile: dict) -> bool:
    image_path = vm_image_path(profile)
    if image_path.is_file():
        print(f"VM image already exists at {image_path}, skipping install.")
        return True

    print(f"No VM image found at {image_path}, running install script...")
    exit_code = run_shell_script(
        INSTALL_SCRIPT, profile["arch"], profile["version"], profile["kernel_version"]
    )
    if exit_code != 0:
        print(f"install.sh failed with exit code {exit_code}", file=sys.stderr)
        return False
    return True


def start_vm(profile: dict) -> bool:
    exit_code = run_shell_script(
        RUN_SCRIPT, profile["arch"], profile["version"], profile["kernel_version"]
    )
    if exit_code != 0:
        print(f"run.sh failed with exit code {exit_code}", file=sys.stderr)
        return False
    return True


def get_vm_connection_info(profile: dict) -> dict:
    return {"host": "localhost", "port": VM_PORT, "username": profile["username"]}


def wait_for_vm_ready(connection_info: dict) -> bool:
    deadline = time.monotonic() + VM_READY_TIMEOUT_SECONDS
    host = connection_info["host"]
    port = connection_info["port"]

    while time.monotonic() < deadline:
        probe = subprocess.run(
            [
                "ssh",
                "-p", str(port),
                "-o", "ConnectTimeout=3",
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                f"{connection_info['username']}@{host}",
                "true",
            ],
            check=False,
            capture_output=True,
        )
        if probe.returncode == 0:
            print(f"VM is reachable at {host}:{port}.")
            return True
        time.sleep(VM_READY_POLL_INTERVAL_SECONDS)

    print(f"VM did not become reachable within {VM_READY_TIMEOUT_SECONDS}s.", file=sys.stderr)
    return False


def write_vm_connection_info(connection_info: dict) -> None:
    VM_CONNECTION_INFO_PATH.parent.mkdir(parents=True, exist_ok=True)
    VM_CONNECTION_INFO_PATH.write_text(json.dumps(connection_info, indent=2))
    print(f"Wrote VM connection info to {VM_CONNECTION_INFO_PATH}.")


def run_agent_investigation() -> int:
    if not RECIPE_PATH.is_file():
        print(f"Recipe not found at {RECIPE_PATH} -- create it before running this.", file=sys.stderr)
        return 1

    result = subprocess.run(["goose", "run", "--recipe", str(RECIPE_PATH)], check=False)
    return result.returncode


def main() -> None:
    if not ensure_vm_image(PROFILE):
        sys.exit(1)

    if not start_vm(PROFILE):
        sys.exit(1)

    connection_info = get_vm_connection_info(PROFILE)

    if not wait_for_vm_ready(connection_info):
        sys.exit(1)

    write_vm_connection_info(connection_info)

    exit_code = run_agent_investigation()
    if exit_code != 0:
        print(f"Goose exited with a non-zero code: {exit_code}", file=sys.stderr)
        sys.exit(exit_code)

    print("Investigation finished. Check reports/ for the output.")


if __name__ == "__main__":
    main()