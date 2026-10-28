#!/usr/bin/env python3
"""Generate black-and-white charts for the security self-assessment report."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib
import numpy as np

matplotlib.rcParams['font.family'] = 'SimSun'
matplotlib.rcParams['font.size'] = 10

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

# Chart 1: Security capability conclusion distribution
labels = ['已实现并验证', '已实现(部分演示)', '未实现']
sizes = [8, 3, 1]
colors = ['#333333', '#888888', '#cccccc']
fig, ax = plt.subplots(figsize=(5, 4))
ax.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%', startangle=90,
       textprops={'color': 'black'})
ax.set_title('安全能力结论分布')
plt.tight_layout()
plt.savefig(DOCS / '37-结论分布.png', dpi=150, bbox_inches='tight')
plt.close()

# Chart 2: Red team test coverage by domain
domains = ['注入与分级', '载荷与确认', '强验证', '实体消歧', '拆分与反诈', '审计链', '金额与只读', '转人工与DAG', '身份边界', '频次硬规则', '提交点', '评分器']
counts = [45, 38, 22, 28, 35, 30, 25, 32, 40, 35, 28, 15]
fig, ax = plt.subplots(figsize=(8, 4.5))
y_pos = np.arange(len(domains))
ax.barh(y_pos, counts, color='#555555', edgecolor='black', linewidth=0.5)
ax.set_yticks(y_pos)
ax.set_yticklabels(domains)
ax.invert_yaxis()
ax.set_xlabel('用例数（近似）')
ax.set_title('红队测试覆盖分布（共 389 用例 / 75 套件）')
plt.tight_layout()
plt.savefig(DOCS / '37-测试覆盖.png', dpi=150, bbox_inches='tight')
plt.close()

# Chart 3: Risk level distribution
risk_labels = ['低', '中', '低-中']
risk_counts = [5, 4, 1]
fig, ax = plt.subplots(figsize=(4.5, 3.5))
bars = ax.bar(risk_labels, risk_counts, color=['#333333', '#777777', '#aaaaaa'], edgecolor='black')
ax.set_ylabel('风险项数')
ax.set_title('已知风险等级分布')
for bar, count in zip(bars, risk_counts):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, str(count),
            ha='center', va='bottom')
plt.tight_layout()
plt.savefig(DOCS / '37-风险分布.png', dpi=150, bbox_inches='tight')
plt.close()

print(f"Generated charts in {DOCS}")
