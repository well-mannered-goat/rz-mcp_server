# Rizin Debugger Bug-Hunting Agent

An AI agent (Goose) that hunts for bugs in the Rizin debugger by writing
small test programs, compiling and running them inside a disposable QEMU
VM, and investigating anything that looks wrong.

## How it works

```
main.py
  1. Boots a QEMU VM (installing it once if it doesn't exist yet)
  2. Waits until the VM is reachable
  3. Writes VM connection info to data/vm_connection.json
  4. Launches Goose with prompts/investigate.yaml

Goose (the agent)
  - Has zero capabilities of its own
  - Can only call tools exposed by mcp_server/tools.py
  - Reasons about what to try; tools.py does the actual work

tools.py (MCP server, runs as a Goose extension)
  - discover_capabilities / get_vm_environment  -> orient the agent
  - create_test_json                            -> register a new test, get a test_id
  - build_binary / test_binary                  -> compile + run a probe binary on the VM (SSH)
  - get_binary_context                          -> real symbols/addresses via Rizin's own analysis
  - update_test_commands / run_test             -> run Rizin commands, capture output
  - read_source_file / search_rizin_source      -> investigate Rizin's own source
  - create_report / submit_report               -> write the final Markdown report
```

Every test is tracked by a `test_id`; the agent never has to remember or
retype long values (binary paths, addresses) itself — it just passes the
ID and the tool looks up the rest.

## Directory layout

```
main.py               deterministic VM setup + launches Goose
scripts/               install.sh (one-time OS install), run.sh (boot existing image)
mcp_server/tools.py    the agent's tools (MCP server)
prompts/investigate.yaml  the agent's mission + which tools it can use
data/                  vm_connection.json (host/port/user/pass, written by main.py)
tests/                 one JSON file per test_id (commands, binary path, etc.)
context/               rizin-debugger-commands reference
reports/               final report.md gets saved here
rizin/                 local Rizin source tree (for read_source_file / search_rizin_source)
vm_config.json         VM's OS/arch/compiler info, given to the agent
images/                the QEMU disk image(s)
```

## Running it

```bash
goose configure          # one-time: set LLM provider + register tools.py as an extension
python main.py            # boots the VM and runs one investigation
```

Output lands in `reports/report.md`.

## Current scope

- One test investigation per run (no multi-test loop yet).
- The agent can only investigate and hypothesize — it cannot modify Rizin's source or fix anything.
- VM setup is deterministic (`main.py`/shell scripts); the agent never provisions infrastructure itself.
- SSH auth currently uses a fixed password (dev-only setup, not for shared/production use).