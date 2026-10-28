/**
 * 实体消歧(Payee Resolution)
 *
 * 这是"智能转账"里最像人、也最容易被做假的地方。
 * 用户说"给老王转 500",系统必须回答:
 *   ① 老王是谁? ② 有几个可能的老王? ③ 凭什么认为是他?
 *
 * 设计原则:
 *   ★ 宁可澄清,绝不猜测。
 *     转错人的代价远高于多问一句。因此本模块在置信度不足时
 *     **返回澄清请求而不是最佳猜测**。这是可以拿去答辩的核心主张。
 *
 * 解析顺序(从最可靠到最不可靠):
 *   1. 显式标识:账号 / 完整手机号        → 唯一确定
 *   2. 别名/昵称精确匹配("老妈"→王秀兰)  → 高置信,这是"越用越懂你"的来源
 *   3. 姓名精确匹配                        → 唯一则高置信,多个则澄清
 *   4. 姓名模糊匹配(包含/一字之差)        → 中置信,需澄清确认
 *   5. 历史指代("上次那个房东")            → 依赖交易上下文检索
 *   6. 无法解析                            → 澄清,并给出可点选候选
 */

import type {
  ClarificationRequest,
  Payee,
  Transaction,
} from "../types.ts";
import { fmtYuan } from "../util/format.ts";
import type { PayeeRef } from "../intent/schema.ts";

/** 消歧结果 */
export type ResolutionOutcome =
  | {
      kind: "resolved";
      payee: Payee;
      /** 解析依据,写入审计与确认卡 */
      basis: ResolutionBasis;
      confidence: number;
    }
  | {
      kind: "ambiguous";
      candidates: PayeeCandidate[];
      clarification: ClarificationRequest;
    }
  | {
      kind: "not_found";
      clarification: ClarificationRequest;
    };

export interface ResolutionBasis {
  /** 解析方式 */
  method: "account_no" | "phone" | "alias" | "exact_name" | "fuzzy_name" | "history";
  /** 人话说明,用于确认卡回显:"你说的'老妈'我理解为王秀兰" */
  explanation: string;
}

/** 候选收款人 —— 带用于消歧的特征,这是交互体验的关键 */
export interface PayeeCandidate {
  payeeId: string;
  name: string;
  /** 副标题:银行 + 脱敏账号,帮助用户区分同名 */
  subLabel: string;
  /** 消歧提示:"上月转账 2 次""最近一次 3 天前" */
  hint?: string;
  /** 匹配得分,仅用于排序,不展示给用户 */
  score: number;
  /** 是否在客户白名单 */
  isWhitelisted: boolean;
  /** 是否本人名下账户 */
  isSelfOwned: boolean;
  /** 是否首次(影响风险分级,需要在澄清阶段就告诉用户) */
  isFirstTime: boolean;
  /** ★ 可用于选择的全部"可辨认文本"(姓名、别名、银行、尾号) */
  selectableTexts: string[];
}

/**
 * 由候选人的可见特征生成"可用于选择的文本"列表。
 *
 * ★ 设计原则:用户只能选择他**看得见**的东西。
 *   之前只认姓名和候选序号,而界面上明明展示了"备注名:张伟设计""招商银行""尾号 1222"——
 *   用户自然会照着念"备注叫张伟设计的那个",系统却答不上来,只能反复要求"请回复姓名或手机号"。
 *   更糟的是提示语让用户"回复手机号",而界面上只显示 `136****2222`(中间四位被打码了),
 *   用户根本没法完整输入 —— 这是一个自相矛盾的提示。
 *
 *   正确做法:把界面上展示过的每一个可辨认特征都纳入选择依据。
 */
export function buildSelectableTexts(payee: Payee): string[] {
  const texts = new Set<string>();

  // 姓名
  if (payee.name) texts.add(payee.name);

  // 备注名/别名 —— 界面上标注为"备注名:xxx",用户最常用这个来指代
  for (const alias of payee.aliases ?? []) {
    if (alias && alias.length >= 2) texts.add(alias);
  }

  // 银行名(全称与简称)—— "招行那个""农行的"
  if (payee.bankName) {
    texts.add(payee.bankName);
    const short = bankShortName(payee.bankName);
    if (short) texts.add(short);
  }

  // 账号尾号 —— "尾号 1222 那个"
  const digits = (payee.maskedAccountNo ?? "").replace(/\D/g, "");
  if (digits.length >= 4) texts.add(digits.slice(-4));

  // 手机号尾四位 —— 界面上显示的是 136****2222,只有后四位可用
  const phoneDigits = (payee.phone ?? "").replace(/\D/g, "");
  if (phoneDigits.length >= 4) texts.add(phoneDigits.slice(-4));

  return [...texts].filter((t) => t.length >= 2);
}

/** 银行全称 → 常用简称(用户口语里几乎只用简称) */
export function bankShortName(fullName: string): string | null {
  const map: Array<{ re: RegExp; short: string }> = [
    { re: /工商银行/, short: "工行" },
    { re: /建设银行/, short: "建行" },
    { re: /农业银行/, short: "农行" },
    { re: /中国银行/, short: "中行" },
    { re: /招商银行/, short: "招行" },
    { re: /交通银行/, short: "交行" },
    { re: /邮政储蓄/, short: "邮储" },
    { re: /民生银行/, short: "民生" },
    { re: /兴业银行/, short: "兴业" },
    { re: /浦发银行/, short: "浦发" },
    { re: /中信银行/, short: "中信" },
    { re: /光大银行/, short: "光大" },
    { re: /平安银行/, short: "平安" },
  ];
  for (const m of map) {
    if (m.re.test(fullName)) return m.short;
  }
  return null;
}

export interface ResolveContext {
  customerId: string;
  /** 客户画像中的常用收款人(用于加分) */
  frequentPayeeIds: string[];
  /** 近期交易(用于历史指代解析) */
  recentTransactions: Transaction[];
  now: number;
}

// ============================================================================
// 主解析函数
// ============================================================================

export interface PayeeDirectory {
  searchPayees(customerId: string, query: { name?: string; phone?: string; limit?: number }): Promise<Payee[]>;
  resolveAlias(customerId: string, alias: string): Promise<Payee | null>;
  getPayee(customerId: string, payeeId: string): Promise<Payee | null>;
}

export async function resolvePayee(
  ref: PayeeRef,
  ctx: ResolveContext,
  directory: PayeeDirectory,
): Promise<ResolutionOutcome> {
  switch (ref.by) {
    case "account_no":
      return resolveByAccountNo(ref, ctx, directory);
    case "phone":
      return resolveByPhone(ref, ctx, directory);
    case "alias":
      return resolveByAlias(ref, ctx, directory);
    case "name":
      return resolveByName(ref, ctx, directory);
    case "history":
      return resolveByHistory(ref, ctx, directory);
    default:
      return {
        kind: "not_found",
        clarification: {
          question: "请问这笔钱要转给谁?您可以直接说姓名、手机号,或者说收款人的昵称。",
          kind: "disambiguate_payee",
        },
      };
  }
}

// ============================================================================
// 1. 账号
// ============================================================================

async function resolveByAccountNo(
  ref: PayeeRef,
  ctx: ResolveContext,
  directory: PayeeDirectory,
): Promise<ResolutionOutcome> {
  const accountNo = ref.accountNo ?? "";
  if (accountNo.length < 8) {
    return {
      kind: "not_found",
      clarification: {
        question: `账号「${accountNo}」看起来不完整,请提供完整账号,或改用姓名/手机号。`,
        kind: "missing_account",
      },
    };
  }
  // 账号通常不在目录中(新收款人),此时走"未收录但可转账"路径
  const matches = await directory.searchPayees(ctx.customerId, { limit: 50 });
  const hit = matches.find((p) => (p.maskedAccountNo ?? "").endsWith(accountNo.slice(-4)));
  if (hit) {
    return {
      kind: "resolved",
      payee: hit,
      basis: { method: "account_no", explanation: `按账号尾号 ${accountNo.slice(-4)} 匹配到收款人` },
      confidence: 0.9,
    };
  }
  return {
    kind: "not_found",
    clarification: {
      question: `我没有找到账号为「${accountNo}」的收款人记录。如果是新收款人,请同时告诉我收款人姓名,以便我们核对户名与账号是否一致。`,
      kind: "disambiguate_payee",
    },
  };
}

// ============================================================================
// 2. 手机号
// ============================================================================

async function resolveByPhone(
  ref: PayeeRef,
  ctx: ResolveContext,
  directory: PayeeDirectory,
): Promise<ResolutionOutcome> {
  const phone = (ref.phone ?? ref.raw).replace(/\D/g, "");
  if (phone.length < 4) {
    return {
      kind: "not_found",
      clarification: { question: "请提供完整的手机号,或至少后四位。", kind: "disambiguate_payee" },
    };
  }

  const matches = await directory.searchPayees(ctx.customerId, { phone, limit: 10 });

  if (matches.length === 1) {
    const payee = matches[0]!;
    return {
      kind: "resolved",
      payee,
      basis: {
        method: "phone",
        explanation: `手机号 ${maskPhoneForDisplay(phone)} 对应收款人「${payee.name}」(${payee.bankName})`,
      },
      confidence: 0.95,
    };
  }

  if (matches.length > 1) {
    return {
      kind: "ambiguous",
      candidates: buildCandidates(matches, ctx),
      clarification: buildDisambiguation(matches, ctx, `手机号 ${maskPhoneForDisplay(phone)} 匹配到多个收款人`),
    };
  }

  // 未收录:这是**首次转账**的典型场景,由上层走"新增收款人 + 户名核验"
  return {
    kind: "not_found",
    clarification: {
      question: `手机号 ${maskPhoneForDisplay(phone)} 还不在您的收款人名单里。请告诉我收款人的姓名,我会核对户名后再转账。`,
      kind: "missing_account",
    },
  };
}

// ============================================================================
// 3. 别名/昵称 —— "越用越懂你" 的来源
// ============================================================================

async function resolveByAlias(
  ref: PayeeRef,
  ctx: ResolveContext,
  directory: PayeeDirectory,
): Promise<ResolutionOutcome> {
  const alias = ref.alias ?? ref.raw;

  // ★ 拒绝"延续词假人名":如「再转500」里的「再转」。
  //   这类片段来自解析器的边界误判,语义上是"再来一笔",不是收款人。
  //   这里返回 not_found 会打断上下文继承;因此显式把它当作
  //   "本轮没有收款人"处理 —— 让上层有机会从上下文继承。
  if (isContinuationToken(alias)) {
    return {
      kind: "not_found",
      clarification: {
        question: "这轮您没有说收款人。要沿用刚才那一位吗?如果换人,请告诉我姓名或昵称。",
        kind: "disambiguate_payee",
      },
    };
  }

  const hit = await directory.resolveAlias(ctx.customerId, alias);
  if (hit) {
    return {
      kind: "resolved",
      payee: hit,
      basis: {
        method: "alias",
        explanation: `您说的「${alias}」我记得是「${hit.name}」(${hit.bankName})`,
      },
      confidence: 0.95,
    };
  }

  // 别名未命中 → 先试"去掉自称前缀"的形式,再降级为姓名搜索
  // ★ 为什么必须处理"我"前缀:「我妈」「我的房东」「俺媳妇」是极自然的说法,
  //   而别名表里存的是「老妈」「房东」。实测踩过:用户说「给我妈转200」,
  //   收款人被**原样当成"我妈"**一路写进确认卡与交易,既没解析成人,
  //   还触发了一个假的"首次转账"警告。用户讲亲属/熟人时几乎一定带"我"。
  const strippedSelf = alias.replace(/^(我|我的|俺|俺的|咱|咱的|我家|我们家)/, "").trim();
  if (strippedSelf.length >= 1 && strippedSelf !== alias) {
    const hit2 = await directory.resolveAlias(ctx.customerId, strippedSelf);
    if (hit2) {
      return {
        kind: "resolved",
        payee: hit2,
        basis: {
          method: "alias",
          explanation: `您说的「${alias}」我记得是「${hit2.name}」(${hit2.bankName})`,
        },
        confidence: 0.92,
      };
    }
  }

  const asName = await resolveByName({ ...ref, by: "name", name: alias }, ctx, directory);
  if (asName.kind === "resolved") return asName;

  // 姓名搜索也没命中,再用去前缀形式搜一次(覆盖"我妈"→"妈"这类)
  if (strippedSelf.length >= 1 && strippedSelf !== alias) {
    return resolveByName({ ...ref, by: "name", name: strippedSelf }, ctx, directory);
  }
  return asName;
}

/**
 * 判断一个片段是不是"延续词假人名"。
 *
 * 背景:中文里「再转500」「还转500」「又转500」都没有收款人,
 * 但朴素解析可能把"再转"当成一个名字。这类片段有共同特征:
 * 以延续词开头且很短,并且第二字是动作动词。
 */
export function isBogusPayeeRef(ref: PayeeRef): boolean {
  // ★ 必须同时检查 name 与 alias。
  //   离线解析器对"再给X转"这类句子可能把 X 填在 name 里而不是 alias 里,
  //   只查 alias 会漏掉,导致"再给房东转5800"被误判成延续表述、
  //   继承了上一条的收款人(实测就是这个现象:该转给陈建国,却转给了王秀兰)。
  const candidates = [ref.alias, ref.name, ref.raw].filter((v): v is string => typeof v === "string" && v.length > 0);
  return candidates.some((c) => isContinuationToken(c));
}

export function isContinuationToken(token: string): boolean {
  if (token.length < 2 || token.length > 3) return false;
  const CONTINUATION = new Set(["再", "还", "又", "也", "顺", "另"]);
  const VERBS = new Set(["转", "打", "汇", "付", "给", "交", "缴", "来", "多"]);
  return CONTINUATION.has(token[0]!) && VERBS.has(token[1]!);
}

// ============================================================================
// 4. 姓名
// ============================================================================

async function resolveByName(
  ref: PayeeRef,
  ctx: ResolveContext,
  directory: PayeeDirectory,
): Promise<ResolutionOutcome> {
  const name = ref.name ?? ref.raw;
  if (!name || name.length === 0) {
    return {
      kind: "not_found",
      clarification: { question: "请告诉我收款人的姓名。", kind: "disambiguate_payee" },
    };
  }

  const matches = await directory.searchPayees(ctx.customerId, { name, limit: 10 });

  if (matches.length === 0) {
    return {
      kind: "not_found",
      clarification: {
        question: `您的收款人名单里没有「${name}」。请确认姓名,或提供对方的手机号/账号。`,
        kind: "disambiguate_payee",
      },
    };
  }

  // 精确匹配唯一 → 直接解析
  const exact = matches.filter((p) => p.name === name);
  if (exact.length === 1) {
    const payee = exact[0]!;
    // 若还有别的模糊匹配,但精确匹配唯一且在白名单/有历史,则采纳精确匹配
    const hasConflict = matches.some((p) => p.name !== name);
    if (!hasConflict || payee.isWhitelisted || payee.novelty.successCount > 0) {
      return {
        kind: "resolved",
        payee,
        basis: {
          method: "exact_name",
          explanation: `姓名「${name}」唯一匹配到「${payee.name}」(${payee.bankName} ${
            payee.maskedAccountNo ?? ""
          })`,
        },
        confidence: hasConflict ? 0.85 : 0.98,
      };
    }
  }

  // ★ 同名多候选 → 必须澄清。这是本系统最重要的安全主张之一。
  if (exact.length > 1) {
    return {
      kind: "ambiguous",
      candidates: buildCandidates(exact, ctx),
      clarification: buildDisambiguation(
        exact,
        ctx,
        `有 ${exact.length} 位收款人都叫「${name}」,需要您确认是哪一位`,
      ),
    };
  }

  // 只有模糊匹配 → 也必须澄清(可能打错字,也可能记错名字)
  return {
    kind: "ambiguous",
    candidates: buildCandidates(matches, ctx),
    clarification: buildDisambiguation(
      matches,
      ctx,
      `没有找到完全叫「${name}」的收款人,您是想转给下面哪一位?`,
    ),
  };
}

// ============================================================================
// 5. 历史指代 —— "还是上次那个房东"
// ============================================================================

async function resolveByHistory(
  ref: PayeeRef,
  ctx: ResolveContext,
  directory: PayeeDirectory,
): Promise<ResolutionOutcome> {
  const hint = ref.historyHint;
  const counterparties = ctx.recentTransactions.filter((t) => t.direction === "out" && t.counterpartyId);

  if (counterparties.length === 0) {
    return {
      kind: "not_found",
      clarification: {
        question: "我最近没有找到您的转账记录。您可以直接告诉我收款人的姓名或手机号。",
        kind: "disambiguate_payee",
      },
    };
  }

  // 按最近时间排序取候选;若有描述线索则做文本过滤
  const seen = new Set<string>();
  const ordered: Transaction[] = [];
  for (const t of counterparties) {
    if (t.counterpartyId && !seen.has(t.counterpartyId)) {
      seen.add(t.counterpartyId);
      ordered.push(t);
    }
  }

  let filtered = ordered;
  if (hint?.description) {
    const d = hint.description;
    const keywordMatch = ordered.filter(
      (t) =>
        t.counterpartyName.includes(d) ||
        (t.memo ?? "").includes(d) ||
        (t.category ?? "").includes(d),
    );
    if (keywordMatch.length > 0) filtered = keywordMatch;
  }

  // 解析出对应收款人
  const resolved: Array<{ payee: Payee; tx: Transaction }> = [];
  for (const t of filtered.slice(0, 6)) {
    if (!t.counterpartyId) continue;
    const p = await directory.getPayee(ctx.customerId, t.counterpartyId);
    if (p) resolved.push({ payee: p, tx: t });
  }

  if (resolved.length === 0) {
    return {
      kind: "not_found",
      clarification: {
        question: "我没能确定您指的是哪位收款人,请直接说姓名或手机号。",
        kind: "disambiguate_payee",
      },
    };
  }

  if (resolved.length === 1) {
    const { payee, tx } = resolved[0]!;
    return {
      kind: "resolved",
      payee,
      basis: {
        method: "history",
        explanation: `根据您最近一次(${formatRelative(tx.ts, ctx.now)})的转账记录,我理解为「${payee.name}」${
          tx.memo ? `(备注:${tx.memo})` : ""
        }`,
      },
      confidence: 0.8,
    };
  }

  // 多个历史对象 → 澄清,并展示每笔的历史特征帮助回忆
  const candidates = resolved.map(({ payee, tx }) => {
    const base = buildCandidates([payee], ctx)[0]!;
    return {
      ...base,
      hint: `${formatRelative(tx.ts, ctx.now)}转过 ${formatMoney(tx.amount)}${tx.memo ? ` · ${tx.memo}` : ""}`,
    };
  });

  return {
    kind: "ambiguous",
    candidates,
    clarification: {
      question: "您最近的转账对象有这几位,请问是哪一位?",
      kind: "disambiguate_payee",
      candidates: candidates.map((c) => ({
        id: c.payeeId,
        label: c.name,
        ...(c.subLabel ? { subLabel: c.subLabel } : {}),
        ...(c.hint ? { hint: c.hint } : {}),
      })),
    },
  };
}

// ============================================================================
// 候选构造(交互体验的核心:让用户一眼区分同名的人)
// ============================================================================

function buildCandidates(matches: Payee[], ctx: ResolveContext): PayeeCandidate[] {
  return matches
    .map((p) => {
      const recent = ctx.recentTransactions.filter((t) => t.counterpartyId === p.payeeId);
      const lastTx = recent.length > 0 ? recent.reduce((a, b) => (a.ts > b.ts ? a : b)) : null;

      const hints: string[] = [];
      if (p.isSelfOwned) hints.push("本人账户");
      if (p.novelty.successCount > 0) {
        hints.push(`转过 ${p.novelty.successCount} 次`);
        if (lastTx) hints.push(`最近 ${formatRelative(lastTx.ts, ctx.now)}`);
      } else if (!p.isSelfOwned) {
        hints.push("首次转账");
      }
      if (p.isWhitelisted) hints.push("已加入常用");

      const subParts: string[] = [p.bankName];
      if (p.maskedAccountNo) subParts.push(p.maskedAccountNo);
      if (p.aliases && p.aliases.length > 0) subParts.push(`备注名:${p.aliases.join("/")}`);

      return {
        payeeId: p.payeeId,
        name: p.name,
        subLabel: subParts.join(" · "),
        hint: hints.join(" · "),
        score: (p.novelty.successCount > 0 ? 2 : 0) + (p.isWhitelisted ? 1 : 0) + (p.isSelfOwned ? 1 : 0),
        isWhitelisted: p.isWhitelisted,
        isSelfOwned: p.isSelfOwned,
        isFirstTime: p.novelty.isFirstTime,
        selectableTexts: buildSelectableTexts(p),
      };
    })
    .sort((a, b) => b.score - a.score);
}

function buildDisambiguation(
  matches: Payee[],
  ctx: ResolveContext,
  question: string,
): ClarificationRequest {
  const candidates = buildCandidates(matches, ctx);
  return {
    question,
    kind: "disambiguate_payee",
    candidates: candidates.map((c) => ({
      id: c.payeeId,
      label: c.name,
      ...(c.subLabel ? { subLabel: c.subLabel } : {}),
      ...(c.hint ? { hint: c.hint } : {}),
    })),
  };
}

// ============================================================================
// 展示工具
// ============================================================================

function maskPhoneForDisplay(phone: string): string {
  const d = phone.replace(/\D/g, "");
  if (d.length >= 11) return `${d.slice(0, 3)}****${d.slice(-4)}`;
  if (d.length >= 7) return `${d.slice(0, 3)}****${d.slice(-2)}`;
  return `****${d.slice(-2)}`;
}

/** 带 ¥ 的金额(口径见 util/format.ts,单一实现) */
const formatMoney = (n: number): string => fmtYuan(n);

function formatRelative(ts: number, now: number): string {
  const diff = now - ts;
  const day = 24 * 60 * 60 * 1000;
  if (diff < 60 * 60 * 1000) return `${Math.max(1, Math.round(diff / 60000))} 分钟前`;
  if (diff < day) return `${Math.round(diff / (60 * 60 * 1000))} 小时前`;
  if (diff < 30 * day) return `${Math.round(diff / day)} 天前`;
  if (diff < 365 * day) return `${Math.round(diff / (30 * day))} 个月前`;
  return `${Math.round(diff / (365 * day))} 年前`;
}
