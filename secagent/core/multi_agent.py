"""
Multi-agent orchestration engine.

Wraps sub-AgentRunners as callable tools so an Orchestrator runner
can dispatch tasks to specialised agents via normal tool-use protocol.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Callable, Optional

from secagent.core.agent_runner import AgentRunner
from secagent.core.config import AgentConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Orchestrator system prompt
# ---------------------------------------------------------------------------

ORCHESTRATOR_PROMPT = """\
你是一名资深渗透测试项目负责人（Orchestrator）。

你的职责是协调多个专业子智能体完成安全评估任务。你可以通过工具调用子智能体，
每个子智能体有独立的专业知识和工具集。

## 工作流程
1. **分析任务**：理解用户目标，拆解为可分配的子任务
2. **调度执行**：按依赖关系调用子智能体（通常侦察优先，再做漏洞评估）
3. **综合报告**：整合所有子智能体的结果，输出结构化的渗透测试报告

## 规则
- 每次调用子智能体只分配一个明确的子任务
- 根据前序结果动态决定下一步行动
- 如果子智能体的结果不够充分，可以再次调用并补充指令
- 最终必须输出包含风险等级、漏洞列表、修复建议的完整报告
- 用中文输出
"""


# ---------------------------------------------------------------------------
# SubAgentTool — wraps an AgentRunner as a tool callable
# ---------------------------------------------------------------------------

class SubAgentTool:
    """Expose a child AgentRunner as a tool the orchestrator can invoke."""

    def __init__(
        self,
        agent_name: str,
        description: str,
        runner: AgentRunner,
        on_event: Callable[[dict], None] | None = None,
    ) -> None:
        self.name = f"dispatch_{agent_name}"
        self.description = (
            f"调用 [{agent_name}] 子智能体执行任务。{description}"
        )
        self.input_schema = {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "分配给该子智能体的具体任务指令",
                }
            },
            "required": ["task"],
        }
        self._agent_name = agent_name
        self._runner = runner
        self._on_event = on_event

    def __call__(self, task: str) -> str:
        if self._on_event:
            self._on_event({
                "type": "info",
                "content": f"[SubAgent:{self._agent_name}] 开始执行: {task[:200]}",
            })
        try:
            result = self._runner.run(task, verbose=False)
        except Exception as exc:
            logger.exception("SubAgent %s failed", self._agent_name)
            result = f"[错误] 子智能体 {self._agent_name} 执行失败: {exc}"
        if self._on_event:
            preview = result[:300] + ("..." if len(result) > 300 else "")
            self._on_event({
                "type": "info",
                "content": f"[SubAgent:{self._agent_name}] 完成 ({len(result)} 字符)",
            })
        return result


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_multi_agent_runner(
    config: AgentConfig,
    sub_agents: list[dict],
    base_tools: list | None = None,
    on_event: Callable[[dict], None] | None = None,
) -> AgentRunner:
    """
    Build an Orchestrator AgentRunner with sub-agent dispatch tools.

    Parameters
    ----------
    config : AgentConfig
        Shared LLM configuration (all sub-agents use same provider).
    sub_agents : list[dict]
        Each dict has keys: name, system_prompt, description, tools (list).
    base_tools : list, optional
        Extra tools to give the orchestrator directly (e.g. record_vulnerability).
    on_event : callable, optional
        Callback for streaming sub-agent status to frontend.

    Returns
    -------
    AgentRunner
        The orchestrator runner, ready to call .run(task).
    """
    dispatch_tools: list[SubAgentTool] = []

    for sa in sub_agents:
        sub_runner = AgentRunner(
            config=config,
            system_prompt=sa.get("system_prompt", ""),
            tools=sa.get("tools", []),
        )
        tool = SubAgentTool(
            agent_name=sa["name"],
            description=sa.get("description", ""),
            runner=sub_runner,
            on_event=on_event,
        )
        dispatch_tools.append(tool)
        logger.info("Registered sub-agent tool: %s", tool.name)

    all_tools = list(base_tools or []) + dispatch_tools

    orchestrator = AgentRunner(
        config=config,
        system_prompt=ORCHESTRATOR_PROMPT,
        tools=all_tools,
    )
    return orchestrator
