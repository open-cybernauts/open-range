"""Custom Gradio tab for OpenRange — cybersecurity range dashboard.

Renders a network topology visualization, live action feed, flag status,
and reward dashboard as a custom tab alongside the default OpenEnv Playground.

Signature matches the gradio_builder contract from OpenEnv.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import gradio as gr


def _range_dashboard_html() -> str:
    """Static HTML for the OpenRange dashboard overview."""
    return """
<div style="font-family: 'SF Mono', 'Fira Code', monospace; max-width: 900px; margin: 0 auto; padding: 16px;">
  <style>
    .range-card {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 12px;
    }
    .range-card h3 {
      color: #58a6ff;
      margin: 0 0 12px 0;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .topo-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 8px;
    }
    .zone-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #8b949e;
      margin-bottom: 4px;
      text-align: center;
    }
    .host-node {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 4px;
      padding: 8px;
      text-align: center;
      font-size: 11px;
      color: #c9d1d9;
      transition: border-color 0.2s;
    }
    .host-node:hover { border-color: #58a6ff; }
    .host-node .icon { font-size: 18px; margin-bottom: 4px; }
    .host-node .name { font-weight: bold; }
    .host-node .ip { color: #8b949e; font-size: 10px; }
    .zone-external .host-node { border-color: #f85149; }
    .zone-dmz .host-node { border-color: #d29922; }
    .zone-internal .host-node { border-color: #3fb950; }
    .zone-mgmt .host-node { border-color: #58a6ff; }
    .reward-bar {
      display: flex;
      align-items: center;
      margin: 6px 0;
    }
    .reward-label {
      width: 110px;
      color: #8b949e;
      font-size: 12px;
    }
    .reward-track {
      flex: 1;
      height: 8px;
      background: #21262d;
      border-radius: 4px;
      overflow: hidden;
    }
    .reward-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s;
    }
    .reward-value {
      width: 50px;
      text-align: right;
      color: #c9d1d9;
      font-size: 12px;
    }
    .flag-row {
      display: flex;
      align-items: center;
      padding: 6px 0;
      border-bottom: 1px solid #21262d;
    }
    .flag-icon { font-size: 16px; margin-right: 8px; }
    .flag-id { color: #c9d1d9; font-size: 12px; flex: 1; }
    .flag-status {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 10px;
    }
    .flag-pending { background: #21262d; color: #8b949e; }
    .flag-captured { background: #238636; color: #fff; }
    .action-log {
      max-height: 200px;
      overflow-y: auto;
      font-size: 11px;
    }
    .action-entry {
      padding: 4px 0;
      border-bottom: 1px solid #21262d;
      display: flex;
    }
    .action-step { color: #8b949e; width: 30px; }
    .action-mode { width: 40px; font-weight: bold; }
    .action-red { color: #f85149; }
    .action-blue { color: #58a6ff; }
    .action-cmd { color: #c9d1d9; flex: 1; font-family: monospace; }
  </style>

  <div class="range-card">
    <h3>Network Topology</h3>
    <div class="topo-grid">
      <div class="zone-external">
        <div class="zone-label">External</div>
        <div class="host-node">
          <div class="icon">&#x1F5A5;</div>
          <div class="name">attacker</div>
          <div class="ip">10.0.0.10</div>
        </div>
        <div class="host-node" style="margin-top:8px">
          <div class="icon">&#x1F6E1;</div>
          <div class="name">firewall</div>
          <div class="ip">10.0.0.2</div>
        </div>
      </div>
      <div class="zone-dmz">
        <div class="zone-label">DMZ</div>
        <div class="host-node">
          <div class="icon">&#x1F310;</div>
          <div class="name">web</div>
          <div class="ip">10.0.1.10</div>
        </div>
        <div class="host-node" style="margin-top:8px">
          <div class="icon">&#x2709;</div>
          <div class="name">mail</div>
          <div class="ip">10.0.1.11</div>
        </div>
      </div>
      <div class="zone-internal">
        <div class="zone-label">Internal</div>
        <div class="host-node">
          <div class="icon">&#x1F4BE;</div>
          <div class="name">db</div>
          <div class="ip">10.0.2.20</div>
        </div>
        <div class="host-node" style="margin-top:8px">
          <div class="icon">&#x1F4C1;</div>
          <div class="name">files</div>
          <div class="ip">10.0.2.21</div>
        </div>
      </div>
      <div class="zone-mgmt">
        <div class="zone-label">Management</div>
        <div class="host-node">
          <div class="icon">&#x1F511;</div>
          <div class="name">ldap</div>
          <div class="ip">10.0.3.20</div>
        </div>
        <div class="host-node" style="margin-top:8px">
          <div class="icon">&#x1F4CA;</div>
          <div class="name">siem</div>
          <div class="ip">10.0.3.21</div>
        </div>
      </div>
    </div>
  </div>

  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
    <div class="range-card">
      <h3>Red Rewards</h3>
      <div class="reward-bar">
        <span class="reward-label">Flag Capture</span>
        <div class="reward-track"><div class="reward-fill" style="width:0%;background:#f85149;"></div></div>
        <span class="reward-value">0.0</span>
      </div>
      <div class="reward-bar">
        <span class="reward-label">Efficiency</span>
        <div class="reward-track"><div class="reward-fill" style="width:80%;background:#d29922;"></div></div>
        <span class="reward-value">0.8</span>
      </div>
      <div class="reward-bar">
        <span class="reward-label">Stealth</span>
        <div class="reward-track"><div class="reward-fill" style="width:100%;background:#3fb950;"></div></div>
        <span class="reward-value">1.0</span>
      </div>
      <div class="reward-bar">
        <span class="reward-label">Anti-Halluc</span>
        <div class="reward-track"><div class="reward-fill" style="width:100%;background:#3fb950;"></div></div>
        <span class="reward-value">0.0</span>
      </div>
    </div>
    <div class="range-card">
      <h3>Blue Rewards</h3>
      <div class="reward-bar">
        <span class="reward-label">Detection</span>
        <div class="reward-track"><div class="reward-fill" style="width:0%;background:#58a6ff;"></div></div>
        <span class="reward-value">0.0</span>
      </div>
      <div class="reward-bar">
        <span class="reward-label">Patch Valid</span>
        <div class="reward-track"><div class="reward-fill" style="width:0%;background:#58a6ff;"></div></div>
        <span class="reward-value">0.0</span>
      </div>
      <div class="reward-bar">
        <span class="reward-label">Availability</span>
        <div class="reward-track"><div class="reward-fill" style="width:100%;background:#3fb950;"></div></div>
        <span class="reward-value">1.0</span>
      </div>
      <div class="reward-bar">
        <span class="reward-label">FP Penalty</span>
        <div class="reward-track"><div class="reward-fill" style="width:100%;background:#3fb950;"></div></div>
        <span class="reward-value">0.0</span>
      </div>
    </div>
  </div>

  <div class="range-card">
    <h3>Flags</h3>
    <div class="flag-row">
      <span class="flag-icon">&#x1F6A9;</span>
      <span class="flag-id">FLAG{...} &mdash; Web Application</span>
      <span class="flag-status flag-pending">pending</span>
    </div>
    <div class="flag-row">
      <span class="flag-icon">&#x1F6A9;</span>
      <span class="flag-id">FLAG{...} &mdash; Database</span>
      <span class="flag-status flag-pending">pending</span>
    </div>
    <p style="color:#8b949e;font-size:11px;margin-top:8px;">
      Use the <strong>Playground</strong> tab to reset and interact. Flags update after <code>submit_flag</code>.
    </p>
  </div>
</div>
"""


def build_openrange_gradio_app(
    web_manager: Any,
    action_fields: List[Dict[str, Any]],
    metadata: Any,
    is_chat_env: bool,
    title: str,
    quick_start_md: str,
) -> gr.Blocks:
    """Build the Custom tab for OpenRange: network topology + dashboard.

    Signature matches the gradio_builder contract (see OpenEnv docs).
    """
    with gr.Blocks(title=f"{title} — Range Dashboard") as blocks:
        gr.Markdown("# Range Dashboard")
        gr.Markdown(
            "This tab shows the **network topology**, reward signals, and flag status. "
            "Use the **Playground** tab to Reset and Step with commands "
            "(e.g. `nmap -sV 10.0.1.0/24`)."
        )
        gr.HTML(value=_range_dashboard_html())
    return blocks
