"""Check the demo client's credential handoff without contacting a server."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "quickstart"))
import inspector


class InspectorHandoff(unittest.TestCase):
    def test_demo_credential_uses_stdin_and_selected_port(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            token = "test-only-not-a-real-credential"
            (data / "mcp-token").write_text(token)
            (data / "state.json").write_text(json.dumps({"port": 18081}))
            with patch.object(inspector.demo, "DATA", data), \
                    patch.object(sys, "argv", ["inspector.py", "--method", "tools/list"]), \
                    patch.object(inspector.subprocess, "run") as run:
                run.return_value.returncode = 7
                self.assertEqual(inspector.main(), 7)
            args, kwargs = run.call_args
            self.assertNotIn(token, " ".join(args[0]))
            self.assertNotIn("shell", kwargs)
            self.assertIn("/dev/stdin", args[0])
            config = json.loads(kwargs["input"])["mcpServers"]["demo"]
            self.assertEqual(config["url"], "http://127.0.0.1:18081/mcp")
            self.assertEqual(config["headers"]["Authorization"], "Bearer " + token)
            self.assertEqual(config["protocolEra"], "legacy")
            self.assertEqual(sorted(p.name for p in data.iterdir()), ["mcp-token", "state.json"])


if __name__ == "__main__":
    unittest.main()
