/**
 * 转账手续费(制度口径的**唯一出处**)
 *
 * ★ 依据:制度语料 `bankcore/corpus/policies.json` → `doc-fee-standard` 1.1:
 *   「转账费用标准:行内转账免手续费;跨行转账单笔 5 万元以下免手续费,
 *     5 万元及以上按 0.05% 收取、最低 2 元最高 50 元。」
 *
 * ★ 为什么必须收在一处:
 *   这句条款会被制度问答**原样引给客户**,而转账确认卡上也会印一行手续费。
 *   原来这两个数字各有各的出处 —— 银行核心写死 `fee: 0`(跨行一律免收),
 *   于是客户问「跨行转 6 万要多少手续费」得到「应收 30 元」,
 *   同一笔转账的确认卡上却写着「免手续费」。系统引的条款打了自己的脸。
 *
 *   规则只在这里写一份:银行核心算"收多少"(bankcore → core 是允许的依赖方向),
 *   能力层只负责把它展示出来。**不知道金额的地方不许报 0** ——
 *   「不知道」和「免费」是两件事,混为一谈正是这次的事故。
 */
import { round2 } from "../util/format.ts";

export const TRANSFER_FEE_RULE = {
  /** 跨行免收手续费的界线:单笔低于此值免收 */
  interbankFreeBelow: 50_000,
  /** 跨行手续费率(0.05%) */
  rate: 0.0005,
  /** 最低收取(元) */
  min: 2,
  /** 最高收取(元) */
  max: 50,
} as const;

/**
 * 跨行转账手续费;行内一律免收。
 * 低于界线免收;达到界线按 0.05% 收取,不足 2 元按 2 元、超过 50 元按 50 元。
 * 例:6 万 → 30 元;5 万 → 25 元;200 万 → 50 元(封顶);4 万 → 免。
 */
export function transferFeeOf(amount: number, interbank: boolean): number {
  if (!interbank) return 0;
  if (!Number.isFinite(amount) || amount < TRANSFER_FEE_RULE.interbankFreeBelow) return 0;
  const raw = amount * TRANSFER_FEE_RULE.rate;
  return round2(Math.min(TRANSFER_FEE_RULE.max, Math.max(TRANSFER_FEE_RULE.min, raw)));
}