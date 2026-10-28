/**
 * 办事台(抽屉顶部的「待您处理 / 为您留意」)
 *
 * ★ 这里只做一件事:把银行核心和会话里已经存在的事实,收成客户能点的条目。
 *   不发明推荐,不把"打算做"写成"已经办成"。
 *   点下去的 `say` 是一句只读或继续对话的话,不是「确认」——
 *   确认仍然发生在对话里的确认卡上。
 */

import { describePendingAction, type PendingAction } from "../../core/src/agent/orchestrator.ts";
import type { ProactiveSuggestion } from "../../core/src/agent/turnExtras.ts";
import type {
  BankSubscription,
  EventPlan,
  Schedule,
  WealthHolding,
  WealthProduct,
  WealthRiskProfile,
} from "../../core/src/types.ts";

const DAY = 24 * 3600 * 1000;
/** 代扣「即将发生」的窗口:月扣至少会落进这 30 天里的某一天 */
const DEBIT_WINDOW_MS = 30 * DAY;
/** 封闭式理财到期提醒窗口 */
const MATURITY_WINDOW_MS = 30 * DAY;
/** 定时转账提醒窗口 */
const SCHEDULE_WINDOW_MS = 14 * DAY;
const MAX_ACTIONS = 4;
const MAX_NOTICES = 2;

export interface DeskItem {
  id: string;
  /** action = 待您处理(和钱或手续直接相关);notice = 为您留意(可以不做) */
  lane: "action" | "notice";
  kind: "pending" | "debit" | "maturity" | "schedule" | "plan" | "assessment" | "suggestion";
  title: string;
  detail: string;
  /** 点一下发给对话的原话。绝不填「确认」 */
  say: string;
  reason: string | null;
  expiresAt: number | null;
}

export interface CustomerDesk {
  actions: DeskItem[];
  notices: DeskItem[];
}

function yuan(n: number): string {
  return `¥${n.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function daysUntil(now: number, at: number): number {
  return Math.ceil((at - now) / DAY);
}

function remainingLabel(now: number, expiresAt: number): string {
  const ms = expiresAt - now;
  if (ms <= 0) return "已过期";
  const minutes = Math.ceil(ms / 60000);
  if (minutes < 60) return `还剩 ${minutes} 分钟`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours < 48) return rest > 0 ? `还剩 ${hours} 小时 ${rest} 分钟` : `还剩 ${hours} 小时`;
  return `还剩 ${Math.ceil(ms / DAY)} 天`;
}

export function buildCustomerDesk(input: {
  now: number;
  pending: PendingAction[];
  subscriptions: BankSubscription[];
  holdings: WealthHolding[];
  products: WealthProduct[];
  schedules: Schedule[];
  plan: EventPlan | null;
  risk: WealthRiskProfile;
  suggestions: ProactiveSuggestion[];
  billHealth?: {
    tag: string;
    tagLabel: string;
    diningMonthlyAvg: number;
    surplusMonthlyAvg: number;
    windowLabel: string;
    reason: string;
  } | null;
  idleCash?: {
    amount: number;
    counterpartyName: string;
    atLabel: string;
    ageHours: number;
    demandAvailable: number;
    threshold: number;
  } | null;
}): CustomerDesk {
  const actions: DeskItem[] = [];

  for (const pending of input.pending.slice(0, 2)) {
    const tier = pending.requiredTier === "strong_auth" ? "需要您本人验证后才会执行" : "需要您确认后才会执行";
    actions.push({
      id: `pending:${pending.pendingId}`,
      lane: "action",
      kind: "pending",
      title: describePendingAction(pending),
      detail: `${tier} · ${remainingLabel(input.now, pending.expiresAt)}。点开只会再问一遍,不会直接办。`,
      say: "刚才那笔待确认办到哪了",
      reason: null,
      expiresAt: pending.expiresAt,
    });
  }

  const upcoming = input.subscriptions
    .filter((s) => s.status === "active" && s.nextDebitAt != null && s.nextDebitAt > input.now && s.nextDebitAt - input.now <= DEBIT_WINDOW_MS)
    .sort((a, b) => (a.nextDebitAt ?? 0) - (b.nextDebitAt ?? 0));
  if (upcoming.length > 0) {
    const soonest = upcoming[0]!;
    const days = daysUntil(input.now, soonest.nextDebitAt!);
    const preview = upcoming
      .slice(0, 3)
      .map((s) => `${s.merchantName} ${yuan(s.amount)}`)
      .join("、");
    const countLabel = `共 ${upcoming.length} 笔`;
    actions.push({
      id: "debit:upcoming",
      lane: "action",
      kind: "debit",
      title: days <= 0 ? `今天将扣款 · 30 天内${countLabel}` : `最近一笔 ${days} 天后扣款 · 30 天内${countLabel}`,
      detail: `${preview}${upcoming.length > 3 ? "等" : ""}。这是本行代扣协议上的下次扣款日,取消仍须您确认;商户侧续费不在此列。`,
      say: "订阅续费提醒",
      reason: "来自银行核心的代扣协议,不是模型推测",
      expiresAt: soonest.nextDebitAt,
    });
  }

  const byCode = new Map(input.products.map((p) => [p.productCode, p]));
  const maturing: Array<{ holding: WealthHolding; at: number; fromBank: boolean }> = [];
  for (const holding of input.holdings) {
    const explicit = holding.maturityAt;
    let at: number | null = explicit != null ? explicit : null;
    let fromBank = explicit != null;
    if (at == null) {
      const termDays = byCode.get(holding.productCode)?.termDays;
      if (termDays == null || termDays <= 0) continue;
      at = holding.firstPurchaseAt + termDays * DAY;
      fromBank = false;
    }
    if (at - input.now > MATURITY_WINDOW_MS) continue;
    if (input.now - at > DAY) continue;
    maturing.push({ holding, at, fromBank });
  }
  maturing.sort((a, b) => a.at - b.at);
  const firstMaturity = maturing[0];
  if (firstMaturity) {
    const days = daysUntil(input.now, firstMaturity.at);
    const when = days <= 0 ? "今天到期" : `${days} 天后到期`;
    actions.push({
      id: `maturity:${firstMaturity.holding.holdingId}`,
      lane: "action",
      kind: "maturity",
      title: `理财「${firstMaturity.holding.productName}」${when}`,
      detail: `当前市值 ${yuan(firstMaturity.holding.marketValue)}。点开只生成续接方案,不会申购,也不会冻结其他资金。`,
      say: "看看这笔理财到期怎么续接",
      reason: firstMaturity.fromBank
        ? "到期日来自持仓上的银行侧记录"
        : "到期日 = 首次申购日 + 产品期限,来自持仓与产品目录",
      expiresAt: firstMaturity.at,
    });
  }

  const schedules = input.schedules
    .filter((s) => s.status === "active" && s.nextRunAt > input.now && s.nextRunAt - input.now <= SCHEDULE_WINDOW_MS)
    .sort((a, b) => a.nextRunAt - b.nextRunAt);
  const nextSchedule = schedules[0];
  if (nextSchedule) {
    const days = daysUntil(input.now, nextSchedule.nextRunAt);
    actions.push({
      id: `schedule:${nextSchedule.scheduleId}`,
      lane: "action",
      kind: "schedule",
      title: days <= 0 ? "今天有一笔定时转账" : `${days} 天后有一笔定时转账`,
      detail: `付给 ${nextSchedule.intent.payee.name} ${yuan(nextSchedule.intent.amount)}。还没执行,取消要另外确认。`,
      say: "我有哪些定时转账",
      reason: "来自已登记且仍在执行中的定时任务",
      expiresAt: nextSchedule.nextRunAt,
    });
  }

  if (input.plan) {
    const executable = input.plan.steps.filter((s) => s.executable).length;
    actions.push({
      id: `plan:${input.plan.planId}`,
      lane: "action",
      kind: "plan",
      title: `方案进行中:${input.plan.eventTitle}`,
      detail: `${remainingLabel(input.now, input.plan.expiresAt)} · 还有 ${executable} 步未执行。方案本身一步都没办。`,
      say: "有哪些关键事件",
      reason: "本会话里生成过、且仍在 30 分钟有效期内的联动方案",
      expiresAt: input.plan.expiresAt,
    });
  }

  const notices: DeskItem[] = [];
  const idle = input.idleCash;
  if (idle) {
    notices.push({
      id: "idle_cash",
      lane: "notice",
      kind: "suggestion",
      title: `${idle.atLabel}有一笔 ${yuan(idle.amount)} 入账,已过 ${idle.ageHours} 小时`,
      detail:
        `「${idle.counterpartyName}」入账后,活期可用仍有 ${yuan(idle.demandAvailable)},不低于 ${yuan(idle.threshold)}。` +
        `货币基金不是存款、不保本。点开只看在售货币类产品,不会申购。`,
      say: "有哪些货币基金",
      reason: "来自活期账户流水和当前活期可用余额",
      expiresAt: null,
    });
  }
  const health = input.billHealth;
  if (health && health.tag !== "none") {
    notices.push({
      id: "bill_health",
      lane: "notice",
      kind: "suggestion",
      title: `${health.windowLabel}财务健康:${health.tagLabel}`,
      detail:
        `餐饮月均 ${yuan(health.diningMonthlyAvg)},月均结余 ${yuan(health.surplusMonthlyAvg)}。` +
        `${health.reason}点开看逐月数字,不会申购。`,
      say: "看看财务健康标签",
      reason: health.reason,
      expiresAt: null,
    });
  }
  if (!input.risk.assessed || input.risk.expired) {
    notices.push({
      id: "assessment",
      lane: "notice",
      kind: "assessment",
      title: input.risk.expired ? "风险测评已过期" : "尚未完成风险测评",
      detail: "首次购买理财前必须先测评。看产品、比产品不受影响,申购会被拦住。",
      say: "做风险测评",
      reason: input.risk.expired ? "测评有效期已过(一年一评)" : "银行侧没有这份客户的有效测评",
      expiresAt: input.risk.validUntil,
    });
  } else if (input.risk.validUntil != null && input.risk.validUntil - input.now <= 45 * DAY) {
    const days = daysUntil(input.now, input.risk.validUntil);
    notices.push({
      id: "assessment-expiring",
      lane: "notice",
      kind: "assessment",
      title: days <= 0 ? "风险测评今天到期" : `风险测评 ${days} 天后到期`,
      detail: "到期后新的申购会被拦住,已有持仓不受影响。",
      say: "做风险测评",
      reason: "测评有效期来自银行侧测评记录",
      expiresAt: input.risk.validUntil,
    });
  }

  for (const suggestion of input.suggestions) {
    if (suggestion.id === "idle_cash" || suggestion.id === "bill_health") continue;
    if (notices.length >= MAX_NOTICES) break;
    notices.push({
      id: `suggestion:${suggestion.id}`,
      lane: "notice",
      kind: "suggestion",
      title: suggestion.text,
      detail: suggestion.reason,
      say: suggestion.say,
      reason: suggestion.reason,
      expiresAt: null,
    });
  }

  return {
    actions: actions.slice(0, MAX_ACTIONS),
    notices: notices.slice(0, input.idleCash || (input.billHealth && input.billHealth.tag !== "none") ? 3 : MAX_NOTICES),
  };
}
