#!/usr/bin/env python3
"""Generate architecture and algorithm charts for the technical design document."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

plt.rcParams['font.family'] = 'SimSun'
plt.rcParams['font.size'] = 9

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

# ---- Chart 1: System layered architecture ----
fig, ax = plt.subplots(figsize=(10, 6))
ax.set_xlim(0, 10)
ax.set_ylim(0, 10)
ax.axis('off')
ax.set_title('系统分层架构（依赖方向始终向内）', fontsize=14, pad=20)

layers = [
    (8.5, '渠道层', 'App / Web / IM / Voice', '#e8e8e8'),
    (6.5, '服务网关层', 'server: 身份令牌 / CORS / CSRF / 节流', '#d0d0d0'),
    (4.5, '领域核心层', 'core: 策略引擎 / 编排器 / 安全模块 / 审计链', '#b8b8b8'),
    (2.5, '大模型层', 'llm: 意图解析（可替换）', '#a0a0a0'),
    (0.5, '银行核心层', 'bankcore: 模拟核心（可替换为真实核心）', '#888888'),
]

for y, name, desc, color in layers:
    rect = FancyBboxPatch((1, y), 8, 1.5, boxstyle="round,pad=0.05",
                          facecolor=color, edgecolor='black', linewidth=1.2)
    ax.add_patch(rect)
    ax.text(5, y + 0.95, name, ha='center', va='center', fontsize=11, weight='bold')
    ax.text(5, y + 0.45, desc, ha='center', va='center', fontsize=9)

# arrows
for y in [8.0, 6.0, 4.0, 2.0]:
    ax.annotate('', xy=(5, y), xytext=(5, y + 0.5),
                arrowprops=dict(arrowstyle='->', color='black', lw=1.5))

ax.text(9.2, 5.5, '依赖方向\n始终向内', ha='center', va='center', fontsize=10,
        bbox=dict(boxstyle='round', facecolor='white', edgecolor='black'))
plt.tight_layout()
plt.savefig(DOCS / '38-架构分层.png', dpi=150, bbox_inches='tight')
plt.close()

# ---- Chart 2: Request processing flow ----
fig, ax = plt.subplots(figsize=(10, 7))
ax.set_xlim(0, 10)
ax.set_ylim(0, 12)
ax.axis('off')
ax.set_title('单回合处理链路（一个请求经过哪些层）', fontsize=14, pad=20)

steps = [
    (11, '用户消息（自然语言）'),
    (10, '1. 渠道信封规范化\nMessageEnvelope'),
    (9, '2. 注入检测\nsecurity/injection.ts'),
    (8, '3. 意图解析（LLM）\nintentParser / deterministic'),
    (7, '4. 反诈信号评估\nsecurity/antiFraud.ts'),
    (6, '5. 实体消歧\nintent/resolvePayee.ts'),
    (5, '6. 风险信号注入\n__payeeRisk / __velocity'),
    (4, '7. 策略裁决（纯函数）\npolicy/engine.ts'),
    (3, '8. 载荷冻结\ncomputePayloadHash'),
    (2, '9. 确认 / 强验证闸门\n回执绑定载荷哈希'),
    (1, '10. 能力执行\ncapabilities/registry.ts'),
    (0, '11. 审计哈希链追加\naudit/hashChain.ts'),
]

for i, (y, text) in enumerate(steps):
    rect = FancyBboxPatch((1.5, y), 7, 0.8, boxstyle="round,pad=0.03",
                          facecolor='#f0f0f0' if i % 2 == 0 else '#e0e0e0',
                          edgecolor='black', linewidth=0.8)
    ax.add_patch(rect)
    ax.text(5, y + 0.4, text, ha='center', va='center', fontsize=8.5)
    if i < len(steps) - 1:
        ax.annotate('', xy=(5, y - 0.15), xytext=(5, y),
                    arrowprops=dict(arrowstyle='->', color='black', lw=1))

ax.text(8.8, 8, '唯一使用\n大模型', ha='center', va='center', fontsize=9,
        bbox=dict(boxstyle='round', facecolor='#ffe0e0', edgecolor='black'))
ax.text(8.8, 4, '永不调用\n大模型', ha='center', va='center', fontsize=9,
        bbox=dict(boxstyle='round', facecolor='#e0ffe0', edgecolor='black'))
plt.tight_layout()
plt.savefig(DOCS / '38-处理链路.png', dpi=150, bbox_inches='tight')
plt.close()

# ---- Chart 3: Risk scoring factors ----
factors = ['收款人新颖度', '金额敞口', '渠道风险', '设备可信', '画像偏离', '时段异常', '拆分特征', '名单命中']
weights = [26, 24, 16, 10, 6, 6, 30, 100]
colors = ['#666666'] * 6 + ['#333333', '#000000']
fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.barh(factors, weights, color=colors, edgecolor='black', linewidth=0.5)
ax.set_xlabel('满分贡献 / 权重')
ax.set_title('风险评分因子权重（0–100 分，阈值 28 / 62）')
for bar, w in zip(bars, weights):
    label = f'{w}' if w < 100 else '顶格 100'
    ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, label,
            va='center', fontsize=9)
ax.set_xlim(0, 110)
plt.tight_layout()
plt.savefig(DOCS / '38-评分因子.png', dpi=150, bbox_inches='tight')
plt.close()

# ---- Chart 4: Permission tiers distribution ----
tiers = ['auto\n直接执行', 'confirm\n用户确认', 'strong_auth\n强验证', 'blocked\n阻断']
descriptions = [
    '余额查询\n流水分析\n收款人检索',
    '小额转账\n定时转账\nAA 收款',
    '大额转账\n首次新收款人\n跨境汇款',
    '改绑手机号\n改密码\n关风控'
]
fig, ax = plt.subplots(figsize=(8, 4))
for i, (tier, desc) in enumerate(zip(tiers, descriptions)):
    rect = FancyBboxPatch((i * 2.2, 0.5), 1.8, 2.5, boxstyle="round,pad=0.05",
                          facecolor=['#e8f5e9', '#fff9c4', '#ffccbc', '#ffcdd2'][i],
                          edgecolor='black', linewidth=1.2)
    ax.add_patch(rect)
    ax.text(i * 2.2 + 0.9, 2.3, tier.split('\n')[0], ha='center', va='center', fontsize=10, weight='bold')
    ax.text(i * 2.2 + 0.9, 1.8, tier.split('\n')[1], ha='center', va='center', fontsize=9)
    ax.text(i * 2.2 + 0.9, 1.0, desc, ha='center', va='center', fontsize=8)
ax.set_xlim(-0.3, 9)
ax.set_ylim(0, 3.5)
ax.axis('off')
ax.set_title('权限分级四档语义与典型操作', fontsize=14, pad=20)
plt.tight_layout()
plt.savefig(DOCS / '38-权限分级.png', dpi=150, bbox_inches='tight')
plt.close()

print(f"Generated tech doc charts in {DOCS}")
