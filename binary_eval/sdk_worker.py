"""OpenHands integration. Only SandboxShellTool executes model-selected commands."""
from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .core import container_runtime, read_json, write_json


def create_agent(cfg, system_prompt, execute):
    """Construct without making a model call; execute is the Docker-only boundary."""
    from pydantic import Field, SecretStr
    from openhands.sdk import LLM, Action, Agent, Observation, TextContent, ToolDefinition
    from openhands.sdk.tool import Tool, ToolExecutor, register_tool

    class ShellAction(Action):
        command: str = Field(description='Bash command to run inside the binary sandbox')

    class ShellObservation(Observation):
        output: str

        @property
        def to_llm_content(self):
            return [TextContent(text=self.output)]

    class ShellExecutor(ToolExecutor):
        def __call__(self, action, conversation=None):
            return ShellObservation(output=execute(action.command))

    class SandboxShellTool(ToolDefinition[ShellAction, ShellObservation]):
        @classmethod
        def create(cls, conv_state=None, **params):
            return [cls(description='Run a command in the isolated binary-analysis container. '
                                    'Only /target/jq and analysis tools are available. Work in /work.',
                        action_type=ShellAction, observation_type=ShellObservation,
                        executor=ShellExecutor())]

    register_tool('BinarySandboxShell', SandboxShellTool)
    m, s = cfg['model'], cfg['sampling']
    llm = LLM(model='openai/' + m['id'], base_url=m['base_url'],
              api_key=SecretStr(os.environ.get(m['api_key_env'], 'local-no-key')),
              usage_id='binary-audit', temperature=s['temperature'], top_p=s['top_p'],
              seed=s['seed'], max_output_tokens=s['max_output_tokens'],
              num_retries=0, timeout=min(120, cfg['limits']['time_budget_seconds']))
    agent = Agent(llm=llm, tools=[Tool(name='BinarySandboxShell')],
                  include_default_tools=['FinishTool', 'ThinkTool'],
                  system_prompt=system_prompt, mcp_config={}, condenser=None)
    return agent, llm


class DockerShell:
    def __init__(self, container, output, timeout):
        self.container, self.output, self.timeout = container, Path(output), timeout
        self.calls = 0

    def __call__(self, command):
        self.calls += 1
        ref = f'tool-{self.calls:04d}.txt'
        path = self.output / ref
        started = time.monotonic()
        # command is an argument to bash INSIDE the container, never a host shell.
        args = [container_runtime(), 'exec', '-w', '/work', self.container,
                'timeout', '--signal=TERM', '--kill-after=2', str(self.timeout),
                'bash', '-c', command]
        with path.open('w', encoding='utf-8') as stream:
            try:
                proc = subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT,
                                      timeout=self.timeout + 10, check=False)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                code = 124
                stream.write('\nHost timeout waiting for Docker exec.\n')
        with (self.output / 'tools.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(dict(command=command, output=ref, exit_code=code,
                                         runtime_seconds=time.monotonic() - started)) + '\n')
        # Preserve full output on disk, bound context growth separately.
        with path.open(encoding='utf-8', errors='replace') as stream:
            text = stream.read(32001)
        truncated = len(text) > 32000
        return f'Evidence reference: {ref}; exit code: {code}\n' + text[:32000] + (
            '\n[Output truncated for context; use narrower commands.]' if truncated else '')


def main(config_path, prompts_path, output_path, container):
    cfg, prompts, out = read_json(config_path), read_json(prompts_path), Path(output_path)
    if importlib.metadata.version('openhands-sdk') != cfg['sdk_version']:
        raise ValueError('Installed SDK version differs from configured pin')
    from openhands.sdk import Conversation
    from openhands.sdk.hooks import HookConfig

    shell = DockerShell(container, out, cfg['limits']['command_timeout_seconds'])
    agent, llm = create_agent(cfg, prompts['system'], shell)

    def on_event(event):
        data = event.model_dump(mode='json')
        with (out / 'events.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(data, ensure_ascii=False) + '\n')
        # Snapshot after every event so partial runs retain available metrics.
        write_json(out / 'metrics.json', llm.metrics.model_dump(mode='json'))
        action = data.get('action') or {}
        if data.get('tool_name') == 'finish' and isinstance(action.get('message'), str):
            (out / 'final.txt').write_text(action['message'], encoding='utf-8')
        message = data.get('llm_message') or {}
        if data.get('source') == 'agent' and message.get('role') == 'assistant':
            text = ''.join(c.get('text', '') for c in message.get('content', []) if isinstance(c, dict))
            if text:
                (out / 'final.txt').write_text(text, encoding='utf-8')

    # No project workspace, user plugin loading, browser, host terminal or editor.
    with tempfile.TemporaryDirectory(prefix='openhands-controller-') as workspace:
        conversation = Conversation(agent=agent, workspace=workspace,
                                    callbacks=[on_event], visualizer=None,
                                    persistence_dir=str(out / 'trajectory'),
                                    delete_on_close=False, plugins=[], hook_config=HookConfig(),
                                    max_iteration_per_run=cfg['limits']['max_iterations'])
        try:
            conversation.send_message(prompts['task'])
            conversation.run()
            write_json(out / 'worker.json', dict(
                execution_status=conversation.state.execution_status.value, tool_calls=shell.calls))
        finally:
            write_json(out / 'metrics.json', llm.metrics.model_dump(mode='json'))
            conversation.close()


if __name__ == '__main__':
    main(*sys.argv[1:])
