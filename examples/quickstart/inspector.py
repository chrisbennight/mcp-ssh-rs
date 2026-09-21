"""Connect MCP Inspector CLI to the running disposable demo on Linux.

Pass Inspector method/tool arguments after this script's name. The demo token
is supplied through stdin, not a command argument or a saved client catalog.
"""

import json
import subprocess
import sys

import demo


def main():
    config = {"mcpServers": {"demo": {
        "type": "streamable-http",
        "url": f"http://127.0.0.1:{demo.state()['port']}/mcp",
        "headers": {"Authorization": "Bearer " + (demo.DATA / "mcp-token").read_text()},
        "protocolEra": "legacy",
    }}}
    result = subprocess.run(
        ["npx", "--yes", "@modelcontextprotocol/inspector@2.4.0", "--cli",
         "--config", "/dev/stdin", "--server", "demo", "--format", "json", *sys.argv[1:]],
        input=json.dumps(config), text=True,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
