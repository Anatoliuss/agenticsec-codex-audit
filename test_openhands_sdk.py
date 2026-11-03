"""Pinned SDK construction test. No Docker or model inference.

Run with the OpenHands environment: python -m unittest test_openhands_sdk -v.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_binary_eval import config


class SDKIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec('openhands.sdk'), 'Install openhands/requirements.txt')
    def test_sdk_exposes_only_sandbox_and_nonexecuting_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'config.json').write_text(json.dumps(config()), encoding='utf-8')
            env = os.environ.copy()
            env.update(HOME=tmp, USERPROFILE=tmp, XDG_CONFIG_HOME=tmp,
                       XDG_CACHE_HOME=tmp, APPDATA=tmp, LOCALAPPDATA=tmp,
                       OPENHANDS_LOG_DIR=tmp, LITELLM_LOCAL_MODEL_COST_MAP='True')
            code = '''
import json, sys
from pathlib import Path
from binary_eval.sdk_worker import create_agent
from openhands.sdk import Conversation
from openhands.sdk.hooks import HookConfig
root = Path(sys.argv[1])
cfg = json.loads((root / "config.json").read_text())
agent, llm = create_agent(cfg, "Test system prompt", lambda command: "captured:" + command)
conversation = Conversation(agent=agent, workspace=str(root / "workspace"),
    persistence_dir=str(root / "trajectory"), delete_on_close=False,
    hook_config=HookConfig(), plugins=[], visualizer=None, max_iteration_per_run=2)
conversation.send_message("A construction test; do not run inference.")
assert set(agent.tools_map) == {"sandbox_shell", "finish", "think"}, agent.tools_map
tool = agent.tools_map["sandbox_shell"].as_executable()
result = tool.executor(tool.action_type(command="printf smoke"))
assert result.output == "captured:printf smoke"
assert llm.seed == 42 and llm.temperature == 0
assert llm.max_output_tokens == 4096
conversation.close()
assert any((root / "trajectory").rglob("*.json")), "trajectory must survive close"
print("SDK boundary and persistence verified")
'''
            proc = subprocess.run([sys.executable, '-c', code, tmp], env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    @unittest.skipUnless(importlib.util.find_spec('openhands.sdk'), 'Install openhands/requirements.txt')
    def test_worker_saves_final_response_events_and_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'config.json').write_text(json.dumps(config()), encoding='utf-8')
            (root / 'prompts.json').write_text(json.dumps(dict(system='Synthetic SDK test', task='Finish now.')))
            env = os.environ.copy()
            env.update(HOME=tmp, USERPROFILE=tmp, XDG_CONFIG_HOME=tmp,
                       XDG_CACHE_HOME=tmp, APPDATA=tmp, LOCALAPPDATA=tmp,
                       OPENHANDS_LOG_DIR=tmp, LITELLM_LOCAL_MODEL_COST_MAP='True')
            code = '''
import json, sys
from pathlib import Path
from unittest.mock import patch
from litellm import ModelResponse
from binary_eval.sdk_worker import main
root = Path(sys.argv[1])
response = ModelResponse(id="synthetic-response", model="test/coder", choices=[{
  "index": 0, "finish_reason": "tool_calls", "message": {
    "role": "assistant", "content": None, "tool_calls": [{
      "id": "call_test", "type": "function", "function": {"name": "finish",
      "arguments": json.dumps({"message": json.dumps({"summary": "synthetic", "findings": []})})}
    }]}}], usage={"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120})
with patch("openhands.sdk.llm.llm.litellm_completion", return_value=response):
    main(str(root / "config.json"), str(root / "prompts.json"), str(root), "unused")
assert json.loads((root / "final.txt").read_text())["summary"] == "synthetic"
assert json.loads((root / "worker.json").read_text())["execution_status"] == "finished"
metrics = json.loads((root / "metrics.json").read_text())
assert metrics["accumulated_token_usage"]["prompt_tokens"] == 100, metrics
assert (root / "events.jsonl").read_text().count("\\n") >= 3
print("Synthetic response persisted; no model or Docker call")
'''
            proc = subprocess.run([sys.executable, '-c', code, tmp], env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == '__main__':
    unittest.main()
