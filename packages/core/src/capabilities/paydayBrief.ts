/**
 * 发薪后分配清单 —— 替代「跨场景联动」的演示场景。
 *
 * 一次只读汇总:工资是否到账、固定支出、订阅扣款、可自由支配估算;
 * 底部给 2～3 个**独立业务**的续办话术(转账/查订阅),不是多步方案、不锁资金、不订外部单。
 */

import { round2 } from "../util/format.ts";
import { accountTypeLabel } from "../util/labels.ts";
import type { Account, ExecutionContext, Transaction } from "../types.ts";
import { fmtSubMoney } from "./subscription.ts";

const DAY = 24 * 3600 * 1000;

function last4(masked: string): string {
  const d = masked.replace(/\D/g, "");
  return d.slice(-4);
}

function findRecentSalary(txs: Transaction[], now: number): { amount: number; at: number; label: string } | null {
  const from = now - 45 * DAY;
  const hits = txs
    .filter(
      (t) =>
        t.direction === "in" &&
        t.ts >= from &&
        (t.category === "工资收入" || /工资|代发|薪/.test(`${t.memo}${t.counterpartyName}`)),
    )
    .sort((a, b) => b.ts - a.ts);
  const top = hits[0];
  if (!top) return null;
  return { amount: top.amount, at: top.ts, label: top.counterpartyName || "工资入账" };
}

function availableTotal(accounts: Account[]): number {
  return round2(
    accounts
      .filter((a) => a.status === "active" && (a.type === "current" || a.type === "savings"))
      .reduce((s, a) => s + a.availableBalance, 0),
  );
}

export interface PaydayBriefResult {
  summary: string;
  salary: { amount: number; at: number; label: string } | null;
  fixedTotal: number;
  subscriptionMonthly: number;
  discretionary: number;
  items: Array<{ title: string; badge: string; tone: "ok" | "medium" | "plain"; lines: string[] }>;
  actions: Array<{ label: string; say: string }>;
}

export async function buildPaydayBrief(ctx: ExecutionContext): Promise<PaydayBriefResult> {
  const now = ctx.now;
  const accounts = await ctx.bank.listAccounts(ctx.customerId);
  const from = now - 45 * DAY;
  const txs = await ctx.bank.fetchForAnalysis(ctx.customerId, { from, to: now });
  const subs = await ctx.bank.listSubscriptions(ctx.customerId);
  const schedules = await ctx.bank.listSchedules(ctx.customerId);

  const salary = findRecentSalary(txs, now);
  const avail = availableTotal(accounts);
  const primary =
    accounts.find((a) => a.status === "active" && (a.type === "current" || a.type === "savings")) ?? accounts[0];

  const activeSubs = subs.filter((s) => s.status === "active");
  const subMonthly = round2(activeSubs.reduce((s, i) => s + i.amount, 0));
  const upcomingSubs = activeSubs.filter((s) => s.nextDebitAt != null && s.nextDebitAt <= now + 30 * DAY);
  const upcomingSubTotal = round2(upcomingSubs.reduce((s, i) => s + i.amount, 0));

  const activeSchedules = schedules.filter((s) => s.status === "active");
  const scheduleTotal = round2(activeSchedules.reduce((s, sch) => s + sch.intent.amount, 0));
  const rentSchedule = activeSchedules.find((s) => /陈建国|房东/.test(s.intent.payee.name));

  const fixedTotal = round2(scheduleTotal + upcomingSubTotal);
  const baseIn = salary?.amount ?? 0;
  const discretionary = round2(Math.max(0, avail - fixedTotal));

  const items: PaydayBriefResult["items"] = [];

  if (salary) {
    items.push({
      title: "近期工资入账",
      badge: "已到账",
      tone: "ok",
      lines: [
        `${new Date(salary.at).toLocaleDateString("zh-CN")} · ${salary.label} · ¥${fmtSubMoney(salary.amount)}`,
        primary
          ? `当前可用余额(含 ${accountTypeLabel(primary.type)} 尾号 ${last4(primary.maskedNo)}): ¥${fmtSubMoney(avail)}`
          : `当前可用余额合计 ¥${fmtSubMoney(avail)}`,
      ],
    });
  } else {
    items.push({
      title: "工资入账",
      badge: "待核对",
      tone: "medium",
      lines: [
        "近 14 天流水里未识别到「工资/代发」入账 —— 若刚到账请说具体日期,我只按流水事实汇总。",
        `当前可用余额 ¥${fmtSubMoney(avail)}`,
      ],
    });
  }

  items.push({
    title: "本月要先留出的固定项",
    badge: "只读",
    tone: "plain",
    lines: [
      activeSchedules.length > 0
        ? `定时转账 ${activeSchedules.length} 笔,合计约 ¥${fmtSubMoney(scheduleTotal)}` +
          (rentSchedule
            ? `(含付给 ${rentSchedule.intent.payee.name} ¥${fmtSubMoney(rentSchedule.intent.amount)})`
            : "")
        : "暂无执行中的定时转账",
      upcomingSubs.length > 0
        ? `30 天内订阅扣款 ${upcomingSubs.length} 笔,约 ¥${fmtSubMoney(upcomingSubTotal)}`
        : "30 天内无已知订阅扣款",
      `固定项合计约 ¥${fmtSubMoney(fixedTotal)}(不含您主动发起的转账)`,
    ],
  });

  items.push({
    title: "扣完固定项后大致可自由支配",
    badge: "估算",
    tone: "ok",
    lines: [
      `可用 ¥${fmtSubMoney(avail)} − 固定项约 ¥${fmtSubMoney(fixedTotal)} ≈ ¥${fmtSubMoney(discretionary)}`,
      "这是按流水与代扣协议算的粗算,不含未录入的大额计划支出;要办转账仍须单独确认。",
    ],
  });

  if (activeSubs.length > 0) {
    items.push({
      title: "自动续费概况",
      badge: "只读",
      tone: "plain",
      lines: [
        `在扣订阅 ${activeSubs.length} 笔,折算每月约 ¥${fmtSubMoney(subMonthly)}`,
        "想关某一项可以说「把某某会员退了」,我会走订阅取消那套确认,不会在这里直接扣款。",
      ],
    });
  }

  const actions: Array<{ label: string; say: string }> = [];
  if (rentSchedule) {
    actions.push({
      label: `付房租 · ${rentSchedule.intent.payee.name}`,
      say: `给${rentSchedule.intent.payee.name}转${rentSchedule.intent.amount}元`,
    });
  } else {
    actions.push({ label: "付房租 · 陈建国", say: "给陈建国转5800元" });
  }
  actions.push({ label: "查自动扣费", say: "帮我查有哪些自动扣费" });
  actions.push({ label: "给妈转生活费", say: "给王秀兰转500元备注生活费" });

  const summary =
    salary != null
      ? `工资 ¥${fmtSubMoney(salary.amount)} 已入账;固定项约 ¥${fmtSubMoney(fixedTotal)},粗算可自由支配约 ¥${fmtSubMoney(discretionary)}`
      : `可用 ¥${fmtSubMoney(avail)};固定项约 ¥${fmtSubMoney(fixedTotal)},粗算可自由支配约 ¥${fmtSubMoney(discretionary)}`;

  return {
    summary,
    salary,
    fixedTotal,
    subscriptionMonthly: subMonthly,
    discretionary,
    items,
    actions: actions.slice(0, 3),
  };
}
