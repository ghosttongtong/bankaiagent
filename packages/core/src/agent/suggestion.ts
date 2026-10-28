/**
 * 个性化主动建议(Suggestion Engine)
 *
 * 需求原话:"增加个性化:记住用户历史业务记录,在合适时机主动给建议
 * (比如『要帮你规划这个月剩余预算吗』等)。"
 *
 * ★ 三条设计立场,决定了它不会变成骚扰:
 *
 *   1. **规则是纯函数。** 输入只有一份事实快照(见 SuggestionFacts),
 *      不查银行、不读会话、不看时间以外的任何外部状态 —— 因此可单测、可复现。
 *      模型不参与建议的产生(与全项目"模型不做裁决"一致)。
 *
 *   2. **每条建议都必须能说出"为什么现在提"。** `reason` 字段是必填的,
 *      而且会被写进审计。一条说不出理由的主动建议,在产品上就是打扰。
 *
 *   3. **恰好给合适的数量。** 太多了像广告,一条都不给则这个功能等于没做。
 *      这里按权重排序、去重、最多 3 条,并且**同一条建议不连续推销**
 *      (冷却由调用方按 `lastShown` 控制,规则本身只负责内容)。
 *
 * ★ 与"常用流程"的联动是本模块最实用的一条:
 *   客户自己存过的流程,过一阵没用,就顺手提醒一句 ——
 *   这比任何"猜你喜欢"都准,因为那是客户自己说的。
 */

import type { ProactiveSuggestion, SuggestionFacts } from "./turnExtras.ts";

// ============================================================================
// 通用规则
// ============================================================================

const DAY = 24 * 3600 * 1000;

/** 常用流程闲置提醒:存了却很久没用 */
export function suggestSavedFlow(facts: SuggestionFacts): ProactiveSuggestion | null {
  /**
   * ★ 必须"用过至少一次"才谈得上"很久没用"。
   *
   *   实测踩到:刚存下一条常用流程(useCount=0、没有 lastUsedAt),
   *   紧接着就弹一句「你的常用流程「转账汇款 · 王秀兰」已经有一阵子没用过了,
   *   要不要再用一次?」—— 而客户**刚刚才办完这件事**。
   *   这种建议不但没用,还会让客户怀疑系统到底记没记住。
   *   (根因:自动保存时 lastUsedAt 为空,被当成"很久以前"。)
   */
  const flows = [...facts.savedFlows]
    .filter((f) => f.useCount > 0 && f.lastUsedAt != null)
    .sort((a, b) => (a.lastUsedAt ?? 0) - (b.lastUsedAt ?? 0));
  const idle = flows.find((f) => facts.now - (f.lastUsedAt ?? 0) >= 3 * DAY);
  if (!idle) return null;
  const days = idle.lastUsedAt ? Math.floor((facts.now - idle.lastUsedAt) / DAY) : null;
  return {
    id: `saved_flow:${idle.templateId}`,
    ruleId: "SUG-SAVED-FLOW-IDLE",
    text: `您的常用流程「${idle.name}」已经有${days != null ? ` ${days} 天` : "一阵子"}没用过了,要不要再用一次?`,
    reason: `客户自己保存过这条流程,最近一次使用在${days != null ? `${days} 天前` : "更早"};常用流程闲置时提醒复用,比任何猜测都准`,
    say: idle.say,
    weight: 55,
    origin: "saved_flow",
  };
}

/** 本月支出已较高:主动提"剩余预算规划" */
export function suggestBudgetPlan(facts: SuggestionFacts): ProactiveSuggestion | null {
  if (facts.monthExpenseCount < 3) return null;
  // 只有在"确实花出去了一笔不小的钱"时才提,避免月初就唠叨
  if (facts.monthExpense < 1000) return null;
  return {
    id: "budget_plan",
    ruleId: "SUG-BUDGET-PLAN",
    text: `本月您已支出 ¥${facts.monthExpense.toLocaleString("zh-CN")}(${facts.monthExpenseCount} 笔)。要帮您规划这个月剩余预算吗?`,
    reason: `客户本月已发生 ${facts.monthExpenseCount} 笔支出、合计 ${facts.monthExpense} 元,且余额 ${facts.availableBalance} 元;给出"还需要花多少、每天可用多少"比只报一个总额有用`,
    say: "帮我规划这个月剩余预算,预算 5000",
    weight: 80,
    origin: "rule",
  };
}

/** 余额偏低提醒 */
export function suggestLowBalance(facts: SuggestionFacts): ProactiveSuggestion | null {
  if (facts.availableBalance > 0 && facts.availableBalance < 300) {
    return {
      id: "low_balance",
      ruleId: "SUG-LOW-BALANCE",
      text: `您活期可用余额只剩 ¥${facts.availableBalance.toLocaleString("zh-CN")} 了,要不要看看这个月的钱都花在哪了?`,
      reason: "可用余额低于 300 元,属于典型的「该看一眼账单」的时刻",
      say: "这个月钱花哪了",
      weight: 85,
      origin: "rule",
    };
  }
  return null;
}

/** 重复的同类业务:提示存成常用流程 */
export function suggestSaveAsFlow(facts: SuggestionFacts): ProactiveSuggestion | null {
  const counts = new Map<string, number>();
  for (const c of facts.sessionCapabilities) counts.set(c, (counts.get(c) ?? 0) + 1);
  const repeated = [...counts.entries()].find(([cap, n]) => n >= 2 && !cap.startsWith("account.") && !cap.startsWith("payee."));
  if (!repeated) return null;
  const [cap] = repeated;
  const label = FLOW_LABEL[cap] ?? cap;
  return {
    id: `save_flow:${cap}`,
    ruleId: "SUG-SAVE-AS-FLOW",
    text: `这次会话里您已经办过两回「${label}」了,要不要把它存成常用流程?下次点一下就办。`,
    reason: `同一会话内重复办理同一类业务(${cap} × ${repeated[1]}),是"值得存为常用流程"的直接证据`,
    say: "把刚才那个存成常用流程",
    weight: 70,
    origin: "history",
  };
}

/** 理财:已购产品收益回看 */
export function suggestWealthReview(facts: SuggestionFacts): ProactiveSuggestion | null {
  if (!facts.recentCapabilities.includes("wealth.purchase")) return null;
  if (!facts.wealthAssessed) return null;
  return {
    id: "wealth_review",
    ruleId: "SUG-WEALTH-REVIEW",
    text: "您上次买的理财现在收益怎么样?要不要看一下持仓?",
    reason: "客户最近申购过理财,回看持仓是最自然的下一步(收益以银行侧净值为准)",
    say: "我的理财持仓收益",
    weight: 45,
    origin: "history",
  };
}

/** 理财将在 7 天内到期:提一句续接方案,不提收益落差 */
export function suggestWealthMaturity(facts: SuggestionFacts): ProactiveSuggestion | null {
  const days = facts.soonestMaturityDays;
  if (days == null || days < 0 || days > 7) return null;
  const when = days <= 0 ? "今天到期" : `${days} 天后到期`;
  return {
    id: "wealth_maturity",
    ruleId: "SUG-WEALTH-MATURITY",
    text: `您有一笔理财${when}。要看同风险的续接方案吗?方案只比较,不会申购。`,
    reason: `持仓上有银行侧到期日,且落在 7 天内(${when})。这时比较产品比事后提醒有用,但比较本身不动钱`,
    say: "看看这笔理财到期怎么续接",
    weight: 92,
    origin: "rule",
  };
}

function yuan(n: number): string {
  return n.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

/** 近几个月流水打出了三档之一:提一句,点开是同一份计算 */
export function suggestBillHealth(facts: SuggestionFacts): ProactiveSuggestion | null {
  const health = facts.billHealth;
  if (!health || health.tag === "none") return null;
  return {
    id: "bill_health",
    ruleId: "SUG-BILL-HEALTH",
    text:
      `${health.windowLabel}的财务健康标签是「${health.tagLabel}」。` +
      `餐饮月均 ¥${yuan(health.diningMonthlyAvg)},月均结余 ¥${yuan(health.surplusMonthlyAvg)}。要看计算过程吗?`,
    reason: health.reason,
    say: "看看财务健康标签",
    weight: 72,
    origin: "rule",
  };
}

/** 活期里有一笔达到门槛、且已经停留超过 48 小时的入账 */
export function suggestIdleCash(facts: SuggestionFacts): ProactiveSuggestion | null {
  const idle = facts.idleCash;
  if (!idle) return null;
  return {
    id: "idle_cash",
    ruleId: "SUG-IDLE-CASH",
    text:
      `${idle.atLabel}「${idle.counterpartyName}」入账 ¥${yuan(idle.amount)},已经 ${idle.ageHours} 小时。` +
      `活期可用仍有 ¥${yuan(idle.demandAvailable)},不低于 ¥${yuan(idle.threshold)}。` +
      `要看在售的货币类产品吗?货币基金不是存款,不保本。看产品不会申购。`,
    reason:
      `活期账户有单笔入账 ${idle.amount} 元,距今 ${idle.ageHours} 小时,超过 48 小时且未超过 30 天;` +
      `活期可用 ${idle.demandAvailable} 元仍不低于门槛 ${idle.threshold} 元`,
    say: "有哪些货币基金",
    weight: 86,
    origin: "rule",
  };
}

/** 账单习惯:看过账单的人往往还想看异常 */
export function suggestAnomalyCheck(facts: SuggestionFacts): ProactiveSuggestion | null {
  if (!facts.recentCapabilities.includes("account.report")) return null;
  if (facts.recentCapabilities.includes("account.detect_anomalies")) return null;
  return {
    id: "anomaly_check",
    ruleId: "SUG-ANOMALY-CHECK",
    text: "要不要顺手帮您扫一遍这个月有没有异常交易?",
    reason: "客户近期看过账单报告,但还没查过异常交易;异常识别是账单场景里最需要主动提示的一项",
    say: "帮我看看这个月有没有异常交易",
    weight: 40,
    origin: "history",
  };
}

const FLOW_LABEL: Record<string, string> = {
  "transfer.submit": "转账",
  "wealth.purchase": "理财申购",
  "wealth.redeem": "理财赎回",
  "card.replace": "补卡",
  "collection.create": "AA 收款",
  "transfer.create_schedule": "定时转账",
};

// ============================================================================
// 组装
// ============================================================================

/** 全部规则(顺序即默认优先级;实际排序按 weight) */
export const SUGGESTION_RULES: Array<(facts: SuggestionFacts) => ProactiveSuggestion | null> = [
  suggestBudgetPlan,
  suggestLowBalance,
  suggestSaveAsFlow,
  suggestSavedFlow,
  suggestWealthReview,
  suggestWealthMaturity,
  suggestBillHealth,
  suggestIdleCash,
  suggestAnomalyCheck,
];

/**
 * 从事实快照产生建议。
 *
 * @param limit 最多返回几条(默认 2:一条主推 + 一条备选,超过两条就变成广告位了)
 */
export function suggestFromFacts(facts: SuggestionFacts, limit = 2): ProactiveSuggestion[] {
  const out: ProactiveSuggestion[] = [];
  const seen = new Set<string>();
  for (const rule of SUGGESTION_RULES) {
    let s: ProactiveSuggestion | null = null;
    try {
      s = rule(facts);
    } catch {
      // 建议是体验增强,任何一条规则出错都不该影响主流程
      s = null;
    }
    if (!s || seen.has(s.id)) continue;
    seen.add(s.id);
    out.push(s);
  }
  return out.sort((a, b) => b.weight - a.weight).slice(0, limit);
}

/**
 * 建议引擎(实现 SuggestionPort)。
 *
 * 宿主机(server)负责组装事实快照;这里只做"规则 → 建议"的纯计算。
 */
export class RuleSuggestionEngine {
  private readonly limit: number;

  constructor(limit = 2) {
    this.limit = limit;
  }

  async suggest(input: SuggestionFacts): Promise<ProactiveSuggestion[]> {
    return suggestFromFacts(input, this.limit);
  }
}
