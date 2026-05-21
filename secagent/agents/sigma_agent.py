"""
SigmaAgent — Single Agent Mode (单智能体模式)

一个全能型渗透测试 Agent，整合所有安全工具，以 sigmaAI 身份独立执行
从侦察到漏洞挖掘的完整测试流程。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from secagent.agents.base_agent import BaseSecAgent
from secagent.core.config import AgentConfig
from secagent.prompts.sigma_single import SIGMA_SINGLE_AGENT_PROMPT
from secagent.tools.network_tools import dns_lookup, port_scan, whois_lookup
from secagent.tools.web_tools import (
    check_common_vulns,
    crawl_links,
    detect_waf,
    fetch_http_headers,
    http_request,
)


# ---------------------------------------------------------------------------
# Vulnerability record dataclass
# ---------------------------------------------------------------------------

@dataclass
class VulnRecord:
    """Structured vulnerability finding."""

    title: str
    description: str
    severity: str          # critical / high / medium / low / info
    vuln_type: str
    target: str
    poc: str = ""
    request_raw: str = ""
    response_raw: str = ""
    impact: str = ""
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_markdown(self) -> str:
        lines = [
            f"## [{self.severity.upper()}] {self.title}",
            f"**类型**: {self.vuln_type}  ",
            f"**目标**: {self.target}  ",
            f"**时间**: {self.timestamp}",
            "",
            f"### 描述\n{self.description}",
            "",
            f"### POC\n{self.poc}",
        ]
        if self.request_raw:
            lines += ["", "### 请求包", "```http", self.request_raw, "```"]
        if self.response_raw:
            lines += ["", "### 响应包", "```http", self.response_raw, "```"]
        if self.impact:
            lines += ["", f"### 影响\n{self.impact}"]
        if self.recommendation:
            lines += ["", f"### 修复建议\n{self.recommendation}"]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# SigmaAgent
# ---------------------------------------------------------------------------

class SigmaAgent(BaseSecAgent):
    """
    单智能体模式 — sigmaAI 渗透测试专家。

    整合全部内置安全工具，以高强度、自主方式对目标执行完整渗透测试。

    用法
    ----
    agent = SigmaAgent()
    report = agent.run(target="https://example.com")
    agent.save_report("pentest_report.md")
    """

    SYSTEM_PROMPT = SIGMA_SINGLE_AGENT_PROMPT

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        super().__init__(config)
        self._findings: list[VulnRecord] = []

    # ------------------------------------------------------------------
    # BaseSecAgent interface
    # ------------------------------------------------------------------

    def _register_tools(self) -> list[Any]:
        """Register all available security tools."""
        return [
            # Network layer
            dns_lookup,
            port_scan,
            whois_lookup,
            # Web layer
            fetch_http_headers,
            http_request,
            detect_waf,
            crawl_links,
            check_common_vulns,
        ]

    def build_task(self, target: str, scope: str = "full", **kwargs: Any) -> str:  # type: ignore[override]
        extra = kwargs.get("extra_instructions", "")
        return (
            f"## 渗透测试任务\n\n"
            f"**目标**: {target}\n"
            f"**范围**: {scope}\n\n"
            f"请对目标执行完整的渗透测试，包括但不限于：\n"
            f"1. 信息收集与资产发现（DNS/WHOIS/端口/目录）\n"
            f"2. WAF / CDN / 技术栈指纹识别\n"
            f"3. Web 漏洞扫描（注入、XSS、SSRF、错误配置等）\n"
            f"4. 安全头 / Cookie / 会话配置审计\n"
            f"5. 敏感路径与接口发现\n"
            f"6. 漏洞利用验证（提供截图或响应证据）\n"
            f"7. 输出结构化漏洞报告\n\n"
            + (f"**额外要求**: {extra}\n" if extra else "")
            + "对每个发现的漏洞，按漏洞记录格式完整输出：标题、描述、严重程度、"
              "类型、目标、POC、原始请求包、原始响应包、影响、修复建议。"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(  # type: ignore[override]
        self,
        target: str,
        scope: str = "full",
        extra_instructions: str = "",
        verbose: bool = True,
    ) -> str:
        """
        对目标执行单智能体渗透测试。

        Args:
            target: 目标 URL、域名或 IP 地址。
            scope: 测试范围描述，默认 'full'。
            extra_instructions: 追加给 Agent 的额外指令。
            verbose: 是否打印工具调用过程。

        Returns:
            完整渗透测试报告（Markdown 格式）。
        """
        return super().run(
            verbose=verbose,
            target=target,
            scope=scope,
            extra_instructions=extra_instructions,
        )

    def save_report(self, path: str, report: str) -> None:
        """将报告写入文件。"""
        header = (
            f"# sigmaAI 渗透测试报告\n\n"
            f"**生成时间**: {datetime.utcnow().isoformat()} UTC\n\n"
            "---\n\n"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(header + report)
        print(f"[+] 报告已保存：{path}")
