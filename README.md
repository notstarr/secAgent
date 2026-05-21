# secAgent

A security testing agent framework built on the **Claude Agent SDK** (Anthropic Python SDK ≥ 0.103).

---

## Architecture

```
secAgent/
├── secagent/
│   ├── core/
│   │   ├── config.py          # AgentConfig (env-based)
│   │   └── agent_runner.py    # Core agentic loop via tool_runner
│   ├── agents/
│   │   ├── base_agent.py      # Abstract BaseSecAgent
│   │   ├── recon_agent.py     # Passive & active reconnaissance
│   │   ├── vuln_agent.py      # Vulnerability assessment
│   │   └── orchestrator.py    # Multi-agent coordinator
│   ├── tools/
│   │   ├── network_tools.py   # dns_lookup, port_scan, whois_lookup
│   │   └── web_tools.py       # fetch_http_headers, http_request,
│   │                          #   detect_waf, crawl_links, check_common_vulns
│   └── main.py                # CLI entry point
└── examples/
    ├── basic_recon.py
    ├── full_assessment.py
    └── custom_tool_example.py
```

### Key Claude SDK features used

| Feature | Usage |
|---|---|
| `@anthropic.beta_tool` | Decorate Python functions → Claude-callable tools |
| `client.beta.messages.tool_runner` | Automatic agentic loop (handles all tool calls) |
| Managed Agents | Optional: `OrchestratorAgent.run_managed()` dispatches sub-agents |
| OpenAI-compat endpoint | Transparent via `OPENAI_COMPAT_*` env vars |

---

## Installation

```bash
cd secAgent
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Copy and fill in credentials:

```bash
cp .env.example .env
# Set ANTHROPIC_API_KEY in .env
```

---

## Quick start

### CLI

```bash
# Recon
secagent recon scanme.nmap.org

# Vulnerability assessment
secagent vuln https://example.com

# Full assessment (recon + vuln + report)
secagent assess scanme.nmap.org
```

### Python API

```python
from secagent.agents.recon_agent import ReconAgent
from secagent.core.config import AgentConfig

agent = ReconAgent(config=AgentConfig())
report = agent.run(target="example.com")
```

### Add a custom tool

```python
import anthropic
from secagent.agents.recon_agent import ReconAgent

@anthropic.beta_tool
def my_tool(target: str) -> str:
    """My custom security tool."""
    return f"Results for {target}"

agent = ReconAgent()
agent.runner.add_tool(my_tool)
agent.run(target="example.com")
```

---

## Agents

| Agent | Class | Purpose |
|---|---|---|
| Recon | `ReconAgent` | DNS, WHOIS, port scan, headers, link crawl |
| Vuln | `VulnAgent` | Security headers, exposed paths, version disclosure |
| Orchestrator | `OrchestratorAgent` | Coordinates Recon + Vuln + synthesis |

---

## Ethical use

This framework is intended for **authorised security testing only**.  
Always obtain written permission before scanning any system you do not own.

---

## License

MIT
