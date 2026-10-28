/**
 * 跨场景事件联动(新场景)—— 通用事件触发器 + 确定性规划引擎。
 *
 * ============================================================================
 * 一、这个场景到底新在哪里
 * ============================================================================
 * 前面几个场景都是"一句话 → 一件事":转账、查账单、买理财、挂失卡、关订阅。
 * 而客户说「我下个月 15 号有个重要纪念日帮我规划下」时,他要的不是一件事,
 * 而是一份**跨场景的联动方案**:账单侧要留出钱、资金侧要锁定、外部侧要下单,
 * 这三件事分别属于三个不同的既有场景,却必须落在同一张时间表上。
 *
 * 所以本模块提供的不是"又一个业务能力",而是一个**机制**:
 *   EventTrigger(关键事件) —— 它是可挂载的:生日、纪念日、发薪日、大额支出预备、
 *   出行,每一个都只是 EVENT_TRIGGERS 里的一条数据,新增一种事件 = 新增一条记录,
 *   不需要动路由、不需要动策略引擎、不需要动确认卡。
 *   触发之后,由 `buildEventPlanSteps` 去**调用既有的确定性引擎**
 *   (账单分析 / 定期支出识别 / 订阅代扣识别 / 理财持仓 / 定时任务),
 *   把它们的结论拼成一张带分级的行动方案。
 *
 * ============================================================================
 * 二、三条不可退让的约束(它们决定了本文件的每一个结构选择)
 * ============================================================================
 * ① **方案 ≠ 执行。**
 *    本文件里没有任何一个函数会改钱、下订单、建任务。它只输出 `EventPlanStep[]`。
 *    真正执行要等客户对**某一步**说确认 —— 而那是另一个能力的事。
 *    这不是"我们没写执行代码",而是结构上就不在一个函数里:
 *    规划引擎拿不到 reserveFunds / placeExternalOrder 的入口。
 *
 * ② **资金操作与外部服务操作必须分开确认。**
 *    所以每一步都带 `domain`(fund / external / read)与 `tier`,
 *    方案渲染时**永不给一个"全部执行"的按钮或话术**,
 *    而是明确分成两组,并告诉客户"这两类要分别确认"。
 *    为什么不是一次确认全做完:它们失败的后果完全不同 ——
 *    锁定资金可以自己解开,外部订单要跟商户协商;把两者绑在一个"确认"上,
 *    客户等于是用一次点击同时授权了两类不可逆程度不同的动作。
 *
 * ③ **每一笔钱的去向与金额,必须在执行之前就写在明面上。**
 *    所以只要一步会动到钱(`fund` / `external`),它就必须带 `funds`
 *    四元组(从哪出 / 给谁 / 多少 / 什么时候)与一句 `disclosure`。
 *    `checkFundDisclosure()` 是纯函数的结构校验 —— 缺任何一项,这一步
 *    在策略引擎那一层会被直接拒绝执行,而不是"提示一下还是让他办"。
 *
 * ============================================================================
 * 三、为什么数字全部由代码算,模型一个字都不参与
 * ============================================================================
 * 方案里出现四类数字:可动用余额、未来固定扣款合计、建议预留金额、商户起订价。
 * 它们分别来自账户、流水/代扣协议、预算规则与商户目录 —— 全部是银行侧事实。
 * 模型在本场景里只负责把"客户说的是哪一类事件、大概是哪一天"翻译成结构化输入;
 * 金额、日期、分级、去向,一个都不经过它(I3)。
 */

import { round2 } from "../util/format.ts";
import { accountTypeLabel } from "../util/labels.ts";
import type {
  Account,
  EventKind,
  EventFundsLeg,
  EventPlan,
  EventPlanStep,
  EventStepDomain,
  ExternalMerchant,
  LifeEvent,
  Transaction,
} from "../types.ts";
import {
  fmtSubDateTime as fmtEventDateTime,
  fmtSubDay as fmtEventDay,
  fmtSubMoney as fmtEventMoney,
  type SubscriptionItem,
} from "./subscription.ts";

/** 方案与步骤的类型定义在 types.ts(它们要进审计与回执),这里转出去便于引用 */
export type { EventPlan, EventPlanStep, EventFundsLeg } from "../types.ts";

const DAY_MS = 24 * 3600 * 1000;

/** 方案有效期:过期必须重新生成 —— 期间余额、扣款日、商户档期都可能变了 */
export const EVENT_PLAN_TTL_MS = 30 * 60 * 1000;

/**
 * 单笔资金操作的建议上限(超过则由策略引擎强制升到强验证档)。
 *
 * ★ 为什么是 1 万,而不是更"看起来安全"的 2 万:
 *   2 万这个数在本演示里恰好等于**客户自设的强验证阈值**(app 侧 profile),
 *   于是客户阈值规则会先一步升级,这条规则永远轮不到生效 ——
 *   它就成了"写了但从来没跑过"的死代码(测试也证不了它)。
 *   1 万让"金额越大越严格"这件事在演示里真的发生:
 *   预留 2,000 → 黄色;预留 12,000 → 红色,并且**能说清是被哪条规则抬上去的**。
 */
export const EVENT_FUND_STEP_WARN_AMOUNT = 10000;

/** 客户自述事件进入规划窗口的天数上限(超过这个跨度就不叫"近期准备") */
export const EVENT_MAX_LEAD_DAYS = 180;

// ============================================================================
// 一、规划引擎的输入:全部来自银行侧与既有引擎
// ============================================================================

/** 既有账单分析引擎的结论(近 30 天) */
export interface EventBillSummary {
  periodLabel: string;
  income: number;
  expense: number;
  net: number;
  topCategories: Array<{ key: string; total: number; count: number }>;
  largest: Array<{ counterpartyName: string; amount: number; category: string; ts: number }>;
}

/** 既有"定期支出识别"引擎的结论 */
export interface EventRecurringItem {
  counterpartyName: string;
  category: string;
  cadence: string;
  avgAmount: number;
  expectedNext: number | null;
}

/** 既有理财引擎的结论(持仓 + 候选产品) */
export interface EventHoldingItem {
  productName: string;
  marketValue: number;
  profit: number;
}

export interface EventProductItem {
  productCode: string;
  name: string;
  riskLevel: string;
  minAmount: number;
  termDays: number | null;
}

/** 既有定时任务 */
export interface EventScheduleItem {
  scheduleId: string;
  amount: number;
  payeeName: string;
  nextRunAt: number | null;
  cadenceLabel: string;
}

export interface EventPlanData {
  now: number;
  accounts: Account[];
  /** 近 6 个月流水(账单分析用) */
  transactions: Transaction[];
  /** 近 30 天账单结论(既有引擎产出) */
  bill: EventBillSummary;
  /** 定期支出(既有引擎产出) */
  recurring: EventRecurringItem[];
  /** 订阅代扣识别结果(既有引擎产出) */
  subscriptions: SubscriptionItem[];
  /** 理财持仓(既有引擎产出) */
  holdings: EventHoldingItem[];
  /** 理财产品候选(既有引擎产出) */
  products: EventProductItem[];
  /** 定时任务(既有引擎产出) */
  schedules: EventScheduleItem[];
  /** 客户已登记/已自述的关键事件 */
  events: LifeEvent[];
  /** 外部服务商户目录 */
  merchants: ExternalMerchant[];
}

// ============================================================================
// 二、事件触发器(本场景的"通用机制"就在这里)
// ============================================================================

/** 一次规划所针对的事件(由触发器 + 客户原话推出) */
export interface PlannedEvent {
  triggerId: string;
  kind: EventKind;
  kindLabel: string;
  title: string;
  occursAt: number;
  leadDays: number;
  /** 客户自述的预算(有则优先) */
  budgetHint?: number;
  /** 客户原话,进审计 */
  rawText: string;
  /** 事件是客户说的,还是系统从数据里认出来的 */
  source: "user_stated" | "bills";
  sourceLabel: string;
}

export interface EventTriggerDef {
  id: string;
  kind: EventKind;
  kindLabel: string;
  /** 触发词:命中即认为客户在说这一类事件 */
  keywords: RegExp;
  /** 提前多少天进入规划窗口 */
  leadDays: number;
  /** 这个触发器会不会主动去商户侧下单(决定它是否可能产生红色步骤) */
  placesExternalOrder: boolean;
  /** 挂载说明 —— 给客户看的"这个触发器会挂什么" */
  mounts: string;
  /**
   * 步骤生成器。
   * ★ 它是**纯函数**:只读 data,不写任何东西,不调用任何外部服务。
   *   这正是"方案生成不会擅自改资金状态"的结构保证。
   */
  build: (data: EventPlanData, event: PlannedEvent) => EventPlanStep[];
}

/** 可动用余额:只算活期/储蓄类,不算信用卡额度(额度不是钱) */
export function availableFunds(accounts: Account[]): { total: number; account: Account | null } {
  const usable = accounts.filter((a) => a.status === "active" && (a.type === "current" || a.type === "savings"));
  const sorted = [...usable].sort((a, b) => b.availableBalance - a.availableBalance);
  return { total: round2(usable.reduce((s, a) => s + a.availableBalance, 0)), account: sorted[0] ?? null };
}

/** 主要入账账户(工资卡):近 6 个月入账金额最大的那个 */
export function primaryIncomeAccount(accounts: Account[], txs: Transaction[]): Account | null {
  const byAccount = new Map<string, number>();
  for (const t of txs) {
    if (t.direction !== "in") continue;
    byAccount.set(t.accountId, (byAccount.get(t.accountId) ?? 0) + t.amount);
  }
  let best: Account | null = null;
  let bestAmount = -1;
  for (const a of accounts) {
    const amt = byAccount.get(a.accountId) ?? 0;
    if (amt > bestAmount) {
      bestAmount = amt;
      best = a;
    }
  }
  return best;
}

/**
 * 建议预留金额。
 *
 * ★ 为什么要有确定性公式而不是"随便给个数":
 *   客户问"帮我规划",最怕的就是系统张口一个金额 —— 那是模型在替他决定花多少钱。
 *   这里的三条输入都是可复核的:客户自己说的预算 > 可动用余额的一成 > 一个下限。
 *   任何一条被改动,方案里的数字都会跟着变,而且审计里能复算出同一条式子。
 */
export function suggestBudget(data: EventPlanData, budgetHint?: number): { amount: number; basis: string } {
  const { total } = availableFunds(data.accounts);
  if (budgetHint != null && budgetHint > 0) {
    return { amount: roundTo(budgetHint, 10), basis: `按您给的预算 ¥${fmtEventMoney(budgetHint)}` };
  }
  const cap = 2000;
  const raw = Math.min(total * 0.1, cap);
  const amount = Math.max(100, roundTo(raw, 10));
  return {
    amount,
    basis: `按可动用余额 ¥${fmtEventMoney(total)} 的一成估算(上限 ¥${fmtEventMoney(cap)},下限 ¥100)`,
  };
}

/** 未来窗口内已知的固定扣款/定期支出(订阅 + 定期支出),按时间排序 */
export function upcomingFixedOutflows(
  data: EventPlanData,
  fromTs: number,
  toTs: number,
): Array<{ name: string; amount: number; at: number; kind: string }> {
  const out: Array<{ name: string; amount: number; at: number; kind: string }> = [];
  for (const s of data.subscriptions) {
    if (s.status === "cancelled" || s.nextDebitAt == null) continue;
    if (s.nextDebitAt < fromTs || s.nextDebitAt > toTs) continue;
    out.push({ name: s.merchantName, amount: s.amount, at: s.nextDebitAt, kind: "订阅代扣" });
  }
  for (const r of data.recurring) {
    if (r.expectedNext == null) continue;
    if (r.expectedNext < fromTs || r.expectedNext > toTs) continue;
    // 订阅已经在上面列过一次,这里去掉重名,避免同一笔钱被算两遍
    if (out.some((o) => o.name === r.counterpartyName)) continue;
    out.push({ name: r.counterpartyName, amount: r.avgAmount, at: r.expectedNext, kind: `定期支出(${r.cadence})` });
  }
  for (const s of data.schedules) {
    if (s.nextRunAt == null || s.nextRunAt < fromTs || s.nextRunAt > toTs) continue;
    out.push({ name: s.payeeName, amount: s.amount, at: s.nextRunAt, kind: "定时任务" });
  }
  return out.sort((a, b) => a.at - b.at);
}

// ---- 步骤构造小工具(保证每一步的口径一致) ----

function stepIdOf(triggerId: string, index: number): string {
  return `${triggerId}-S${index + 1}`;
}

function fundsLeg(from: Account | null, toName: string, amount: number, scheduledAt: number | null): EventFundsLeg {
  return {
    fromAccountId: from?.accountId ?? null,
    fromAccountLabel: from ? `${accountTypeLabel(from.type)} 尾号 ${last4Of(from.maskedNo)}` : "待选择出账账户",
    toName,
    amount: round2(amount),
    currency: "CNY",
    scheduledAt,
  };
}

function disclosureOf(leg: EventFundsLeg, when: string): string {
  return (
    `从「${leg.fromAccountLabel}」出账 ¥${fmtEventMoney(leg.amount)},去向「${leg.toName}」,时间 ${when}` +
    (leg.fromAccountId == null ? "(出账账户尚未指定,确认时请说明)" : "")
  );
}

function readStep(args: {
  triggerId: string;
  index: number;
  title: string;
  detail: string;
  evidence: string[];
  executed: boolean;
}): EventPlanStep {
  return {
    stepId: stepIdOf(args.triggerId, args.index),
    domain: "read",
    domainLabel: "只读准备",
    title: args.title,
    detail: args.detail,
    capability: null,
    tier: "auto",
    tierLabel: "直接办理(只读,不涉及资金)",
    executable: false,
    disclosure: "只读查询,不涉及任何资金变动。",
    evidence: args.evidence,
    executed: args.executed,
  };
}

function fundStep(args: {
  triggerId: string;
  index: number;
  title: string;
  detail: string;
  capability: string;
  leg: EventFundsLeg;
  when: string;
  evidence: string[];
  mode?: "reserve" | "schedule";
}): EventPlanStep {
  return {
    stepId: stepIdOf(args.triggerId, args.index),
    domain: "fund",
    domainLabel: "资金操作",
    title: args.title,
    detail: args.detail,
    capability: args.capability,
    tier: "confirm",
    tierLabel: args.mode === "schedule" ? "需您确认这个定时任务的金额与时间" : "需您确认这笔资金的去向与金额",
    executable: true,
    funds: args.leg,
    fundMode: args.mode ?? "reserve",
    disclosure: disclosureOf(args.leg, args.when),
    evidence: args.evidence,
  };
}

function externalStep(args: {
  triggerId: string;
  index: number;
  title: string;
  detail: string;
  capability: string;
  leg: EventFundsLeg;
  when: string;
  evidence: string[];
}): EventPlanStep {
  return {
    stepId: stepIdOf(args.triggerId, args.index),
    domain: "external",
    domainLabel: "外部服务操作",
    title: args.title,
    detail: args.detail,
    capability: args.capability,
    tier: "strong_auth",
    tierLabel: "需强验证。外部订单提交后,退改须与商户协商。",
    executable: true,
    funds: args.leg,
    disclosure: disclosureOf(args.leg, args.when),
    evidence: args.evidence,
  };
}

/** 从商户目录里按类别挑一家:有档期(bookAheadDays ≤ 剩余天数)优先,评分高者优先 */
function pickMerchant(
  merchants: ExternalMerchant[],
  category: string,
  daysUntil: number,
): ExternalMerchant | null {
  const candidates = merchants
    .filter((m) => m.category === category)
    .filter((m) => m.bookAheadDays <= Math.max(daysUntil, 0) || m.sameDayDelivery)
    .sort((a, b) => b.rating - a.rating || a.minAmount - b.minAmount);
  return candidates[0] ?? null;
}

function merchantStep(
  triggerId: string,
  index: number,
  merchant: ExternalMerchant,
  budgets: { amount: number; from: Account | null; scheduledAt: number; when: string; why: string; now: number },
): EventPlanStep {
  const amount = Math.max(budgets.amount, merchant.minAmount);
  const leg = fundsLeg(budgets.from, merchant.name, amount, budgets.scheduledAt);
  return externalStep({
    triggerId,
    index,
    title: `${merchant.categoryLabel}预约:${merchant.hotItem}`,
    detail:
      `${budgets.why} 选定商户「${merchant.name}」(评分 ${merchant.rating},` +
      `${merchant.sameDayDelivery ? "支持当日送达" : `需提前 ${merchant.bookAheadDays} 天预约`});` +
      `起订 ¥${fmtEventMoney(merchant.minAmount)}。★ 退订政策:${merchant.cancelPolicy}`,
    capability: "event.external_step",
    leg,
    when: budgets.when,
    evidence: [
      `外部商户目录:${merchant.name}(${merchant.categoryLabel},起订 ¥${fmtEventMoney(merchant.minAmount)})`,
      `预约提前量:需 ${merchant.bookAheadDays} 天,当前距预订时间 ${Math.max(0, Math.round((budgets.scheduledAt - budgets.now) / DAY_MS))} 天`,
    ],
  });
}

/**
 * ★ 六类触发器里只有五类(见下方 EVENT_TRIGGERS)。
 *   新增一种事件 = 往那个数组里加一条数据 —— 这就是"通用触发机制"的全部含义:
 *   机制本身不认识"生日"或"发薪日",它只认识"命中了一条触发器,按它的 build 出方案"。
 */

// ============================================================================
// 三、触发器定义(可挂载的 Mock 事件都在这)
// ============================================================================

export const EVENT_TRIGGERS: EventTriggerDef[] = [
  {
    id: "evt_anniversary",
    kind: "anniversary",
    kindLabel: "纪念日",
    keywords: /(纪念日|周年|结婚纪念|相识|在一起的|领证)/,
    leadDays: 14,
    placesExternalOrder: true,
    mounts: "账单回顾(留出预算)→ 锁定礼物预算 → 鲜花/蛋糕预约",
    build: (data, event) => {
      const { account } = availableFunds(data.accounts);
      const budget = suggestBudget(data, event.budgetHint);
      const giftBudget = round2(budget.amount);
      const merchant = pickMerchant(data.merchants, "flower", event.leadDays);
      const steps: EventPlanStep[] = [];

      steps.push(
        readStep({
          triggerId: event.triggerId,
          index: 0,
          title: "先看钱够不够:近 30 天收支与本月固定扣款",
          detail:
            `近 30 天收入 ¥${fmtEventMoney(data.bill.income)}、支出 ¥${fmtEventMoney(data.bill.expense)}、` +
            `净额 ${data.bill.net >= 0 ? "+" : "-"}¥${fmtEventMoney(Math.abs(data.bill.net))};` +
            `当前可动用余额 ¥${fmtEventMoney(availableFunds(data.accounts).total)}。`,
          evidence: [
            `账单分析(近 30 天):收入 ¥${fmtEventMoney(data.bill.income)} / 支出 ¥${fmtEventMoney(data.bill.expense)}`,
            `可动用余额:¥${fmtEventMoney(availableFunds(data.accounts).total)}`,
          ],
          executed: true,
        }),
      );

      const window = upcomingFixedOutflows(data, data.now, event.occursAt + 3 * DAY_MS);
      if (window.length > 0) {
        steps.push(
          readStep({
            triggerId: event.triggerId,
            index: steps.length,
            title: "避开扣款日:事件前后已知的固定扣款",
            detail:
              `事件日前后共有 ${window.length} 笔固定扣款,合计 ¥` +
              `${fmtEventMoney(window.reduce((s, w) => s + w.amount, 0))}:` +
              window.map((w) => `${fmtEventDay(w.at)} ${w.name} ¥${fmtEventMoney(w.amount)}`).join("、") +
              "。★ 预留金额时已经把这些扣款排除在外。",
            evidence: window.map((w) => `${w.kind}:${w.name} ¥${fmtEventMoney(w.amount)} @ ${fmtEventDay(w.at)}`),
            executed: true,
          }),
        );
      }

      steps.push(
        fundStep({
          triggerId: event.triggerId,
          index: steps.length,
          title: `锁定「${event.title}」礼物预算`,
          detail:
            `预留 ¥${fmtEventMoney(giftBudget)}(${budget.basis}),到期日为该事件当天;` +
            "锁定期间这笔钱仍在您名下,只是标记为这笔用途专用,可以随时解开。",
          capability: "event.fund_step",
          leg: fundsLeg(account, `${event.title}礼物预算`, giftBudget, event.occursAt),
          when: `${fmtEventDay(event.occursAt)}(事件当天)`,
          evidence: [`预算口径:${budget.basis}`, `出账账户:${account ? account.maskedNo : "待选择"}`],
        }),
      );

      if (merchant) {
        steps.push(
          merchantStep(event.triggerId, steps.length, merchant, {
            amount: Math.min(round2(budget.amount * 0.35), 520),
            from: account,
            scheduledAt: event.occursAt,
            when: `${fmtEventDay(event.occursAt)}(希望当天送达)`,
            why: `从礼物预算里拿出约三成做一件"当天能送到"的事。`,
            now: data.now,
          }),
        );
      }

      return steps;
    },
  },
  {
    id: "evt_birthday",
    kind: "birthday",
    kindLabel: "生日",
    keywords: /(生日|寿辰|过生|寿宴)/,
    leadDays: 14,
    placesExternalOrder: true,
    mounts: "账单回顾 → 锁定礼物预算 → 蛋糕预约",
    build: (data, event) => {
      const { account } = availableFunds(data.accounts);
      const budget = suggestBudget(data, event.budgetHint);
      const cake = pickMerchant(data.merchants, "cake", event.leadDays);
      const steps: EventPlanStep[] = [];

      steps.push(
        readStep({
          triggerId: event.triggerId,
          index: 0,
          title: "先看钱够不够:近 30 天收支",
          detail:
            `近 30 天净额 ${data.bill.net >= 0 ? "+" : "-"}¥${fmtEventMoney(Math.abs(data.bill.net))},` +
            `可动用余额 ¥${fmtEventMoney(availableFunds(data.accounts).total)}。`,
          evidence: [`账单分析(近 30 天):净额 ¥${fmtEventMoney(data.bill.net)}`],
          executed: true,
        }),
      );
      steps.push(
        fundStep({
          triggerId: event.triggerId,
          index: steps.length,
          title: `锁定生日预算`,
          detail: `预留 ¥${fmtEventMoney(budget.amount)}(${budget.basis})到生日当天。`,
          capability: "event.fund_step",
          leg: fundsLeg(account, "生日预算", budget.amount, event.occursAt),
          when: `${fmtEventDay(event.occursAt)}(生日当天)`,
          evidence: [`预算口径:${budget.basis}`],
        }),
      );
      if (cake) {
        steps.push(
          merchantStep(event.triggerId, steps.length, cake, {
            amount: Math.min(round2(budget.amount * 0.3), 368),
            from: account,
            scheduledAt: event.occursAt,
            when: `${fmtEventDay(event.occursAt)}(生日当天)`,
            why: "生日蛋糕通常需要提前预订,越接近当天可选款式越少。",
            now: data.now,
          }),
        );
      }
      return steps;
    },
  },
  {
    id: "evt_payday",
    kind: "payday",
    kindLabel: "发薪日",
    keywords: /(发薪|发工资|开工资|工资到账|月薪到账|薪水到账)/,
    leadDays: 3,
    placesExternalOrder: false,
    mounts: "上月结余回顾 → 发薪后自动转存(定时任务)",
    build: (data, event) => {
      const incomeAcc = primaryIncomeAccount(data.accounts, data.transactions);
      const spendable = availableFunds(data.accounts);
      const steps: EventPlanStep[] = [];

      steps.push(
        readStep({
          triggerId: event.triggerId,
          index: 0,
          title: "发薪前先看清:上月结余与本月固定扣款",
          detail:
            `近 30 天收入 ¥${fmtEventMoney(data.bill.income)}、支出 ¥${fmtEventMoney(data.bill.expense)},` +
            `结余 ${data.bill.net >= 0 ? "+" : "-"}¥${fmtEventMoney(Math.abs(data.bill.net))};` +
            `本月已识别的定期支出 ${data.recurring.length} 项。`,
          evidence: [
            `账单分析:收入 ¥${fmtEventMoney(data.bill.income)} / 支出 ¥${fmtEventMoney(data.bill.expense)}`,
            `定期支出识别:${data.recurring.length} 项`,
          ],
          executed: true,
        }),
      );

      const save = round2(Math.min(Math.max(data.bill.net, 0) * 0.3, 5000));
      if (save >= 100) {
        steps.push(
          fundStep({
            triggerId: event.triggerId,
            index: steps.length,
            title: "发薪后自动转存一笔(定时任务)",
            detail:
              `在发薪日次日设一笔定时转存 ¥${fmtEventMoney(save)}(按上月结余的三成估算,上限 ¥5,000)。` +
              "★ 定时任务可以在执行前随时取消,不影响您账户里的钱。",
            capability: "event.fund_step",
            leg: fundsLeg(incomeAcc ?? spendable.account, "储蓄账户(自动转存)", save, event.occursAt + DAY_MS),
            when: `${fmtEventDay(event.occursAt + DAY_MS)}(发薪日次日)`,
            mode: "schedule",
            evidence: [
              `结余口径:上月净额 ¥${fmtEventMoney(data.bill.net)} 的三成,上限 ¥5,000`,
              `出账账户:${incomeAcc ? `${incomeAcc.maskedNo}(近 6 个月主要入账账户)` : "待选择"}`,
            ],
          }),
        );
      }

      const products = data.products.slice(0, 2);
      if (products.length > 0) {
        steps.push(
          readStep({
            triggerId: event.triggerId,
            index: steps.length,
            title: "这笔钱可以先放哪(理财侧候选,仅建议不动钱)",
            detail:
              products
                .map((p) => `${p.name}(${p.riskLevel},起购 ¥${fmtEventMoney(p.minAmount)})`)
                .join(";") +
              "。★ 这一步只是**建议**:理财申购是另一个场景的动作,要买我会另外给您看申购确认卡。",
            evidence: [`理财目录:${products.map((p) => p.productCode).join("、")}`],
            executed: true,
          }),
        );
      }
      return steps;
    },
  },
  {
    id: "evt_big_expense",
    kind: "big_expense",
    kindLabel: "大额支出预备",
    keywords: /(大额支出|大额开销|要花一大笔|大笔支出|固定扣款|集中扣款|要准备多少钱|有什么.*支出)/,
    leadDays: 30,
    placesExternalOrder: false,
    mounts: "未来 30 天扣款清单(账单+订阅+定时任务)→ 锁定准备资金",
    build: (data, event) => {
      const from = data.now;
      const to = data.now + event.leadDays * DAY_MS;
      const outflows = upcomingFixedOutflows(data, from, to);
      const total = round2(outflows.reduce((s, o) => s + o.amount, 0));
      const { total: avail, account } = availableFunds(data.accounts);
      const steps: EventPlanStep[] = [];

      steps.push(
        readStep({
          triggerId: event.triggerId,
          index: 0,
          title: `未来 ${event.leadDays} 天要扣哪些钱(账单 + 订阅 + 定时任务)`,
          detail:
            outflows.length === 0
              ? `未来 ${event.leadDays} 天没有识别到已知的固定扣款,可动用余额 ¥${fmtEventMoney(avail)}。`
              : `共 ${outflows.length} 笔、合计 ¥${fmtEventMoney(total)}:` +
                outflows.map((o) => `${fmtEventDay(o.at)} ${o.name} ¥${fmtEventMoney(o.amount)}(${o.kind})`).join(";") +
                `。可动用余额 ¥${fmtEventMoney(avail)},扣除后剩余 ¥${fmtEventMoney(round2(avail - total))}。`,
          evidence: outflows.map((o) => `${o.kind}:${o.name} ¥${fmtEventMoney(o.amount)} @ ${fmtEventDay(o.at)}`),
          executed: true,
        }),
      );

      if (outflows.length > 0) {
        const lastAt = outflows[outflows.length - 1]!.at;
        steps.push(
          fundStep({
            triggerId: event.triggerId,
            index: steps.length,
            title: "为这批扣款锁定一笔准备资金",
            detail:
              `预留 ¥${fmtEventMoney(total)} 到最后一笔扣款日之后,避免"扣款当天余额不足"。"` +
              "★ 锁定只是把这笔钱标记为专用,钱不会被划走。",
            capability: "event.fund_step",
            leg: fundsLeg(account, "近期固定扣款准备", total, lastAt),
            when: `${fmtEventDay(lastAt)}(最后一笔扣款日)`,
            evidence: [`扣款清单合计:¥${fmtEventMoney(total)}(${outflows.length} 笔)`, `可动用余额:¥${fmtEventMoney(avail)}`],
          }),
        );
      }

      const subs = data.subscriptions.filter((s) => s.status === "active");
      if (subs.length > 0) {
        steps.push(
          readStep({
            triggerId: event.triggerId,
            index: steps.length,
            title: "顺手核对:这些还是您要的订阅吗",
            detail:
              `目前有 ${subs.length} 笔订阅代扣在扣款,每月合计 ¥` +
              `${fmtEventMoney(round2(subs.reduce((s, i) => s + i.amount, 0)))}。` +
              "★ 如果其中有不再需要的,可以说「把某某会员关了」,我会走订阅代扣那套流程单独帮您确认。",
            evidence: subs.map((s) => `${s.merchantName} ¥${fmtEventMoney(s.amount)}/${s.cadenceLabel}`),
            executed: true,
          }),
        );
      }
      return steps;
    },
  },
  {
    id: "evt_travel",
    kind: "travel",
    kindLabel: "出行",
    keywords: /(旅游|旅行|出游|出去玩|度假|出行|自驾)/,
    leadDays: 21,
    placesExternalOrder: true,
    mounts: "余额与扣款核对 → 锁定旅费预算 → 酒店/行程预约",
    build: (data, event) => {
      const { account, total } = availableFunds(data.accounts);
      const budget = suggestBudget(data, event.budgetHint);
      const hotel = pickMerchant(data.merchants, "hotel", event.leadDays);
      const steps: EventPlanStep[] = [];

      steps.push(
        readStep({
          triggerId: event.triggerId,
          index: 0,
          title: "出行期间的扣款与可用余额",
          detail:
            `可动用余额 ¥${fmtEventMoney(total)};出行期间(事件后 7 天内)已知固定扣款 ` +
            `${upcomingFixedOutflows(data, event.occursAt - DAY_MS, event.occursAt + 7 * DAY_MS).length} 笔。`,
          evidence: [`可动用余额:¥${fmtEventMoney(total)}`, `账户数:${data.accounts.length}`],
          executed: true,
        }),
      );
      steps.push(
        fundStep({
          triggerId: event.triggerId,
          index: steps.length,
          title: "锁定出行预算",
          detail: `预留 ¥${fmtEventMoney(budget.amount)}(${budget.basis})到出行结束。`,
          capability: "event.fund_step",
          leg: fundsLeg(account, "出行预算", budget.amount, event.occursAt),
          when: `${fmtEventDay(event.occursAt)}(出行日)`,
          evidence: [`预算口径:${budget.basis}`],
        }),
      );
      if (hotel) {
        steps.push(
          merchantStep(event.triggerId, steps.length, hotel, {
            amount: Math.min(round2(budget.amount * 0.5), 800),
            from: account,
            scheduledAt: event.occursAt,
            when: `${fmtEventDay(event.occursAt)}(入住日)`,
            why: "住宿通常越早订越便宜,但也是最需要您确认档期的一项。",
            now: data.now,
          }),
        );
      }
      return steps;
    },
  },
];

/** 触发器清单(给 event.list 用,也是"机制可挂载"的对外说明) */
export function listEventTriggers(): Array<{ id: string; kindLabel: string; leadDays: number; mounts: string }> {
  return EVENT_TRIGGERS.map((t) => ({ id: t.id, kindLabel: t.kindLabel, leadDays: t.leadDays, mounts: t.mounts }));
}

// ============================================================================
// 四、日期解析(事件"什么时候"—— 只解析客户明确说出的日期)
// ============================================================================

function startOfDay(ts: number): number {
  const d = new Date(ts);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function addDays(ts: number, n: number): number {
  return ts + n * DAY_MS;
}

/**
 * 从话里抽出事件发生日期。
 *
 * ★ 三条纪律:
 *   ① 客户没说日期 → 返回 null,由调用方**追问**,绝不默认"下个月今天";
 *   ② 逐字解释"下个月 15 号"里的"下个月"是**相对本月**的自然月,
 *      而不是"30 天后"(否则每月 31 号附近会滑到错误的月份);
 *   ③ 解析出的日期已经过去 → 顺势推到下一个周期(如生日已过 → 明年),
 *      并在方案里如实写出是哪一年 —— 客户说"生日"时想的从来不是去年的那天。
 */
export function parseEventDateHint(text: string, now: number): { occursAt: number; hintText: string } | null {
  const t = text.replace(/\s+/g, "");
  const base = startOfDay(now);

  const rel = t.match(/(今天|明天|后天|大后天)/);
  if (rel) {
    const delta = { 今天: 0, 明天: 1, 后天: 2, 大后天: 3 }[rel[1] as "今天" | "明天" | "后天" | "大后天"];
    return { occursAt: startOfDay(addDays(base, delta)), hintText: rel[1]! };
  }

  const week = t.match(/(下下|下|这|本)(周|星期|礼拜)([一二三四五六日天])/);
  if (week) {
    const weekOffset = week[1] === "下下" ? 2 : week[1] === "下" ? 1 : 0;
    const dayChar = week[3]!;
    const target = { 一: 1, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6, 日: 0, 天: 0 }[dayChar as "一" | "二" | "三" | "四" | "五" | "六" | "日" | "天"];
    const startOfWeek = new Date(base);
    const cur = startOfWeek.getDay();
    let delta = (target - cur + 7) % 7 + weekOffset * 7;
    if (weekOffset === 0 && delta === 0) delta = 7;
    return { occursAt: startOfDay(addDays(base, delta)), hintText: week[0]! };
  }

  // 「下个月15号」「11月15日」「2026年3月2日」
  const abs = t.match(/(?:(\d{4})年)?(?:(\d{1,2})月)?(\d{1,2})(?:日|号)/);
  const monthWord = t.match(/(下下个?月|下个月|这个月|本月|下月)/);
  if (abs) {
    const yearRaw = abs[1];
    const monthRaw = abs[2];
    const dayRaw = Number(abs[3]);
    const d = new Date(base);
    if (yearRaw) {
      d.setFullYear(Number(yearRaw));
      d.setMonth(Number(monthRaw ?? 1) - 1);
    } else if (monthRaw) {
      d.setMonth(Number(monthRaw) - 1);
    } else if (monthWord) {
      const shift = monthWord[1] === "下下个月" || monthWord[1] === "下下月" ? 2 : monthWord[1] === "下个月" || monthWord[1] === "下月" ? 1 : 0;
      d.setMonth(d.getMonth() + shift);
    }
    d.setDate(dayRaw);
    d.setHours(0, 0, 0, 0);
    /**
     * ★ 只有"几号"而没说是哪个月时(如「我15号有个纪念日」):
     *   取**下一个**该日子 —— 本月还没到就是本月,已经过了就是下月。
     *   这与"下个月15号"是两件事,不能混。
     */
    if (!yearRaw && !monthRaw && !monthWord && d.getTime() < base) {
      d.setMonth(d.getMonth() + 1);
    }
    if (d.getTime() < base && !yearRaw) {
      // 说了一个已经过去的绝对日期(如"1月1日"出现在 12 月),按下一年的周期理解
      d.setFullYear(d.getFullYear() + 1);
    }
    return { occursAt: d.getTime(), hintText: abs[0]! };
  }

  const monthOnly = t.match(/(?:(\d{4})年)?(?:(\d{1,2})月)(?:初|中|底)?/);
  if (monthOnly) {
    const d = new Date(base);
    if (monthOnly[1]) d.setFullYear(Number(monthOnly[1]));
    d.setMonth(Number(monthOnly[2]) - 1);
    d.setDate(15);
    d.setHours(0, 0, 0, 0);
    if (d.getTime() < base && !monthOnly[1]) d.setFullYear(d.getFullYear() + 1);
    return { occursAt: d.getTime(), hintText: `${monthOnly[0]}(按月中间估算,可在方案里改)` };
  }

  return null;
}

/** 「发薪日」这类由数据推断的事件:从流水里找最近一次规律性入账,取下一个周期 */
export function inferPayday(data: EventPlanData): number | null {
  const incomes = data.transactions
    .filter((t) => t.direction === "in" && t.amount >= 1000)
    .sort((a, b) => b.ts - a.ts);
  if (incomes.length < 2) return null;
  const last = incomes[0]!;
  const prev = incomes.slice(1).find((t) => Math.abs(t.amount - last.amount) / last.amount < 0.1);
  const interval = prev ? Math.round((last.ts - prev.ts) / DAY_MS) : 30;
  if (interval < 5 || interval > 45) return null;
  let next = last.ts + interval * DAY_MS;
  while (next < data.now) next += interval * DAY_MS;
  return startOfDay(next);
}

// ============================================================================
// 五、匹配与规划
// ============================================================================

/** 从客户话里命中一个触发器(按定义顺序取第一个命中) */
export function matchEventTrigger(text: string): EventTriggerDef | null {
  for (const t of EVENT_TRIGGERS) {
    if (t.keywords.test(text)) return t;
  }
  return null;
}

/** 一次规划请求的输入(路由层解析后填入) */
export interface EventPlanRef {
  /** 客户原话(触发器匹配用) */
  text: string;
  triggerId?: string;
  occursAt?: number;
  title?: string;
  budget?: number;
}

export interface BuildPlanOptions {
  text: string;
  /** 客户说的日期(解析失败则 null) */
  dateHint: { occursAt: number; hintText: string } | null;
  /** 客户给的预算 */
  budgetHint?: number;
  /** 明确指定的事件标题(如"结婚纪念日") */
  titleHint?: string;
  /** 指定触发器 id(位置指代 / 续说时用) */
  triggerId?: string;
  /** 从账单侧推断(「最近有什么大额支出需要提前准备」这类没有日期的话) */
  dataDriven?: boolean;
}

/**
 * 生成一份跨场景联动方案。
 *
 * ★ 纯函数:同一个 data + 同一个 options,永远得到同一份方案。
 *   这一点很重要 —— 客户看到的确认卡、策略引擎裁决的事实、审计里留痕的载荷,
 *   三者必须来自**同一次推导**,否则会出现"卡上写 A、执行的是 B"。
 */
export function buildEventPlan(data: EventPlanData, opts: BuildPlanOptions): EventPlan {
  const trigger =
    (opts.triggerId ? EVENT_TRIGGERS.find((t) => t.id === opts.triggerId) : null) ??
    matchEventTrigger(opts.text) ??
    EVENT_TRIGGERS.find((t) => t.id === "evt_big_expense")!;

  /**
   * ★ 事件日期从哪来,决定方案能说多硬的话:
   *   · 客户说了 → 用客户说的;
   *   · 客户没说但触发器是"发薪日/大额支出预备" → 从流水/扣款清单**推断**;
   *   · 两者都没有 → 用触发器的最小准备窗口做占位,并在方案里标明"日期待确认"。
   */
  let occursAt: number;
  let dateBasis: string;
  const payday = trigger.kind === "payday" ? inferPayday(data) : null;
  if (opts.dateHint) {
    occursAt = opts.dateHint.occursAt;
    dateBasis = `依据:${opts.dateHint.hintText}`;
  } else if (payday != null) {
    occursAt = payday;
    dateBasis = "由流水的规律性入账推断出的下一个发薪日";
  } else {
    occursAt = startOfDay(addDays(data.now, trigger.leadDays));
    dateBasis = `您没说具体日期,先按「${trigger.kindLabel}」的常规准备窗口(${trigger.leadDays} 天)排期 —— 日期可在方案里改`;
  }

  const daysUntil = Math.max(0, Math.round((startOfDay(occursAt) - startOfDay(data.now)) / DAY_MS));
  const event: PlannedEvent = {
    triggerId: trigger.id,
    kind: trigger.kind,
    kindLabel: trigger.kindLabel,
    title: opts.titleHint ?? trigger.kindLabel,
    occursAt,
    leadDays: trigger.leadDays,
    ...(opts.budgetHint != null ? { budgetHint: opts.budgetHint } : {}),
    rawText: opts.text,
    source: opts.dateHint ? "user_stated" : trigger.kind === "payday" || trigger.kind === "big_expense" ? "bills" : "user_stated",
    sourceLabel: opts.dateHint ? "客户自述" : trigger.kind === "payday" || trigger.kind === "big_expense" ? "由账单/流水推断" : "客户自述",
  };

  const steps = trigger.build(data, event);

  const fundSteps = steps.filter((s) => s.domain === "fund").length;
  const externalSteps = steps.filter((s) => s.domain === "external").length;
  const fundTotal = round2(steps.filter((s) => s.domain === "fund").reduce((sum, s) => sum + (s.funds?.amount ?? 0), 0));
  const externalTotal = round2(steps.filter((s) => s.domain === "external").reduce((sum, s) => sum + (s.funds?.amount ?? 0), 0));

  const sources = [
    "账单分析(近 30 天收支与大户)",
    `定期支出识别(${data.recurring.length} 项)`,
    `订阅代扣识别(${data.subscriptions.length} 笔)`,
    data.holdings.length > 0 ? `理财持仓(${data.holdings.length} 只)` : "理财目录查询",
    data.schedules.length > 0 ? `定时任务(${data.schedules.length} 个)` : "定时任务查询",
  ];

  return {
    planId: `EP${String(Math.abs(hashOf(`${trigger.id}:${occursAt}:${data.now}:${steps.length}`))).slice(0, 10)}`,
    eventId: trigger.id,
    eventTitle: event.title,
    eventKind: trigger.kind,
    occursAt,
    daysUntil,
    generatedAt: data.now,
    expiresAt: data.now + EVENT_PLAN_TTL_MS,
    steps,
    notDoing: [
      "不会替您下单,也不会替您付款。每一步须逐条确认后才会执行。",
      "不会改动账户余额。「锁定」只是将该金额标记为指定用途,资金仍在本人名下,可解除。",
      "不会自动办理理财申购或赎回。如需购买理财,将另行出具申购确认。",
      "不会代为决定金额。方案中的金额均写明口径,可直接修改。",
    ],
    sources,
    summary:
      `${event.title}(${fmtEventDay(occursAt)},${daysUntil} 天后 · ${dateBasis}):` +
      `共 ${steps.length} 步 —— 只读准备 ${steps.filter((s) => s.domain === "read").length} 步(已完成)` +
      // ★ 金额为 0 的那一类**不写进摘要**:「外部服务操作 0 步(合计 ¥0.00,需强验证)」
      //   读起来像"有一个 0 元的外部操作在等你",客户会以为自己漏看了什么。
      //   摘要只列真实存在的操作,没提到的就是没有。
      (fundSteps > 0 ? `、资金操作 ${fundSteps} 步(合计 ¥${fmtEventMoney(fundTotal)},需您确认)` : "") +
      (externalSteps > 0 ? `、外部服务操作 ${externalSteps} 步(合计 ¥${fmtEventMoney(externalTotal)},需强验证)` : "") +
      (fundSteps === 0 && externalSteps === 0 ? ";这一版没有需要您确认的操作" : "") +
      "。★ 方案本身没有执行任何一步。",
    fundTotal,
    externalTotal,
  };
}

// ============================================================================
// 六、结构校验:每一笔钱的去向与金额必须能被交代
// ============================================================================

export interface DisclosureGap {
  stepId: string;
  domain: EventStepDomain;
  reason: string;
}

/**
 * 检查方案/步骤里"资金去向披露"是否完整。
 *
 * ★ 这是"合规要求"的机器可执行版本:
 *   原话是"涉及跨场景时,必须事先明确告知每一笔资金去向和金额"。
 *   靠提示词写"记得告知"是**请求**;靠这个函数是**保证** ——
 *   缺任何一项,执行入口就拒绝,而不是"提醒一下仍然放行"。
 */
export function checkFundDisclosure(steps: EventPlanStep[]): DisclosureGap[] {
  const gaps: DisclosureGap[] = [];
  for (const s of steps) {
    if (s.domain === "read") continue;
    if (!s.funds) {
      gaps.push({ stepId: s.stepId, domain: s.domain, reason: "这一步会动到钱,但没有资金去向信息(从哪出/给谁/多少/什么时候)" });
      continue;
    }
    if (!(s.funds.amount > 0)) gaps.push({ stepId: s.stepId, domain: s.domain, reason: "金额缺失或非正数" });
    if (!s.funds.toName || s.funds.toName.trim().length === 0) gaps.push({ stepId: s.stepId, domain: s.domain, reason: "没有写清钱的去向(收款人/商户)" });
    if (!s.funds.currency) gaps.push({ stepId: s.stepId, domain: s.domain, reason: "币种缺失" });
    if (!s.disclosure || s.disclosure.trim().length === 0) gaps.push({ stepId: s.stepId, domain: s.domain, reason: "没有可展示的披露口径" });
  }
  return gaps;
}

// ============================================================================
// 七、渲染(给客户看的话,全部由代码拼,模型不许改写金额)
// ============================================================================

export function renderEventPlan(plan: EventPlan): string {
  const lines: string[] = [];
  lines.push(`${plan.eventTitle} —— ${fmtEventDateTime(plan.occursAt)}(${plan.daysUntil} 天后)`);
  lines.push("");
  lines.push(plan.summary);
  lines.push("");

  const reads = plan.steps.filter((s) => s.domain === "read");
  if (reads.length > 0) {
    lines.push("【已完成 · 只读准备】");
    for (const s of reads) {
      lines.push(`· ${s.title}`);
      lines.push(`  ${s.detail}`);
    }
    lines.push("");
  }

  const funds = plan.steps.filter((s) => s.domain === "fund");
  if (funds.length > 0) {
    lines.push("【第一步 · 资金操作(需确认)】");
    for (const [i, s] of funds.entries()) {
      lines.push(`${i + 1}. ${s.title}`);
      lines.push(`   金额与去向:${s.disclosure}`);
      lines.push(`   说明:${s.detail}`);
      lines.push(`   ${s.tierLabel}`);
    }
    lines.push("");
  }

  const externals = plan.steps.filter((s) => s.domain === "external");
  if (externals.length > 0) {
    lines.push("【第二步 · 外部服务操作(需强验证)】");
    for (const [i, s] of externals.entries()) {
      lines.push(`${i + 1}. ${s.title}`);
      lines.push(`   金额与去向:${s.disclosure}`);
      lines.push(`   说明:${s.detail}`);
      lines.push(`   ${s.tierLabel}`);
    }
    lines.push("");
  }

  lines.push("【这份方案不会做什么】");
  for (const n of plan.notDoing) lines.push(`· ${n}`);
  lines.push("");
  lines.push("【怎么往下走】");
  lines.push("· 资金操作与外部服务操作分开确认。确认哪一步,只办理那一步。");
  if (funds.length > 0) lines.push(`· 想先办资金操作,就说「执行资金操作」或「${funds[0]!.title}」。`);
  if (externals.length > 0) lines.push(`· 如需外部下单,请回复「执行外部操作」或「${externals[0]!.title}」。该步须先完成强验证。`);
  lines.push("· 如需修改金额、日期或去掉某一步,请直接说明,系统将重新生成方案。");
  return lines.join("\n");
}

/** 触发器清单渲染(演示"通用机制可挂载") */
export function renderEventTriggerList(): string {
  const lines: string[] = ["事件触发器:", ""];
  for (const [i, t] of EVENT_TRIGGERS.entries()) {
    lines.push(`${i + 1}. ${t.kindLabel}(${t.id})`);
    lines.push(`   识别词:${t.keywords.source}`);
    lines.push(`   准备窗口:提前 ${t.leadDays} 天进入规划`);
    lines.push(`   触发后会挂载:${t.mounts}`);
  }
  lines.push("");
  lines.push("新增事件类型只需增加一条触发器数据,不必改路由、策略引擎或确认卡。");
  lines.push("无论挂载哪些触发器,资金操作与外部服务操作均分开确认。");
  return lines.join("\n");
}

/** 客户已登记的事件渲染 */
export function renderLifeEventList(events: LifeEvent[], now: number): string {
  if (events.length === 0) {
    return (
      "目前没有您登记过的关键事件。\n" +
      "请直接说明日期与事项,例如「11月15号是我结婚纪念日,帮我规划一下」。系统将登记并生成方案。"
    );
  }
  const lines: string[] = [`您登记的关键事件(${events.length} 个):`, ""];
  const sorted = [...events].sort((a, b) => a.occursAt - b.occursAt);
  for (const [i, e] of sorted.entries()) {
    const days = Math.round((startOfDay(e.occursAt) - startOfDay(now)) / DAY_MS);
    lines.push(
      `${i + 1}. ${e.title}(${e.kindLabel})—— ${fmtEventDay(e.occursAt)}` +
        `${days >= 0 ? `(${days} 天后)` : "(已过)"},来源:${e.sourceLabel}` +
        `${e.budgetHint != null ? `,预算 ¥${fmtEventMoney(e.budgetHint)}` : ""}`,
    );
    if (e.note) lines.push(`   ${e.note}`);
  }
  lines.push("");
  lines.push("如需方案,请指明事项并回复「帮我规划一下」。");
  return lines.join("\n");
}

// ============================================================================
// 工具
// ============================================================================

function roundTo(n: number, unit: number): number {
  return Math.round(n / unit) * unit;
}

function last4Of(maskedNo: string): string {
  const digits = maskedNo.replace(/\D/g, "");
  return digits.slice(-4) || "----";
}

function hashOf(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) | 0;
  }
  return h;
}