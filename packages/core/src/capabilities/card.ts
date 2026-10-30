/**
 * 卡片管理引擎(Card Engine)—— 全部纯函数,零 LLM,零 I/O
 *
 * ★ 与场景二 `billAnalysis.ts`、场景三 `wealth.ts` 完全同构的设计立场:
 *   "谁算的"必须能一句话回答。卡片场景里,有四个判断错一次就会直接伤害客户:
 *
 *     ① **额度调整不是即时生效** —— 这是申请,不是执行。
 *        说错一次,客户会以为额度已经提到 5 万,然后刷卡失败。
 *     ② **能提多少** —— 报高了是空头承诺,报低了是白跑一趟。
 *     ③ **限制能不能解、找谁解** —— 司法冻结说成"我帮你解开"是严重的合规事故;
 *        信息不完整说成"银行不给你解"则让客户白等。
 *     ④ **挂失补卡换号还是保号、要不要激活、要不要重设密码** ——
 *        这四件事的差异必须在**操作之前**告知,而不是等卡寄到了再说。
 *
 *   因此本文件只允许出现确定性函数:给定同样的输入,永远得到同样的输出。
 *   所有阈值(6 个月、3 个月、T+N 天)都写成具名常量,便于审计与答辩解释。
 *
 * ★ 一条贯穿全文件的原则:**数据里不给"我们帮你提额"留位置**。
 *   本文件产出的任何结果都带 `wording` / `ourPart` / `bankPart` 三段式口径,
 *   把"我们帮你做"与"银行审核说了算"从文案层就分开 ——
 *   模型可以复述,但不能改变这个结构。
 */

import type {
  BankCard,
  CardKind,
  CardRestriction,
  CardStatus,
  RestrictionCause,
  RestrictionChannel,
} from "../types.ts";

// ============================================================================
// 一、行业规则常量(所有阈值集中在此,便于审计)
// ============================================================================

/**
 * 额度调整的资格门槛。
 *
 * ★ 三条规则都来自真实银行卡业务惯例,它们的共同点是:
 *   **它们全是"时间"约束,而不是"金额"约束** ——
 *   所以客户无法通过"多刷几笔"来加速,系统也不能用金额逻辑去推测。
 */
export const LIMIT_RULES = {
  /** 新开户或刚调额不久的客户,通常需用卡满 6 个月再申请提额 */
  minMonthsSinceOpen: 6,
  /** 距上次额度调整不足 3 个月的,需等冷却期满 */
  minMonthsSinceAdjustment: 3,
  /** 提额申请的银行审核时效(工作日)—— 用于告知"多久出结果" */
  reviewBusinessDays: 3,
  /** 单次提额幅度上限(相对当前额度) */
  maxIncreaseRatio: 1,
  /** 单次提额后的额度上限(风控兜底) */
  maxResultingLimit: 500_000,
} as const;

/** 补卡时效：保留原号需要重新制卡并迁移卡号,等待更久 */
export const REPLACEMENT_ETA_DAYS = {
  /** 换号补卡:普通制卡 */
  newNumber: 5,
  /** 保留原号:需要制卡 + 卡号迁移,更慢 */
  keepNumber: 12,
  /** 到期换卡 / 损坏换卡 */
  renewal: 5,
} as const;

/** 新开户/加办卡的审批时效(工作日) */
export const CARD_APPLICATION_REVIEW_BUSINESS_DAYS = 5;

// ============================================================================
// 二、文案标签(唯一来源,任何展示路径都必须用它)
// ============================================================================

export const CARD_KIND_LABELS: Record<CardKind, string> = {
  credit: "信用卡",
  debit: "借记卡",
  virtual: "虚拟卡",
};

export const CARD_STATUS_LABELS: Record<CardStatus, string> = {
  active: "正常",
  lost: "已挂失",
  frozen: "已冻结(银行/司法侧)",
  pending_activation: "未激活",
  replacement_in_transit: "补卡在途",
  closed: "已销卡",
  expired: "已过期",
};

export const RESTRICTION_CAUSE_LABELS: Record<RestrictionCause, string> = {
  abnormal_transaction: "异常交易",
  incomplete_information: "信息不完整",
  judicial_freeze: "司法冻结",
  security_risk: "安全风险",
  self_setting: "客户自设限额",
};

export const RESTRICTION_CHANNEL_LABELS: Record<RestrictionChannel, string> = {
  agent_application: "可在这里提交解除申请(转银行审核)",
  native_self_service: "需您在 App 安全流程中自助完成",
  authority_document_only: "只能凭有权机关的解除文书办理",
};

/** 卡片的状态是否属于"当前不可用于交易" */
export function isCardBlocked(status: CardStatus): boolean {
  return status !== "active";
}

/** 卡片是否已挂失/冻结 —— 紧急状态判定 */
export function isCardLostOrFrozen(card: BankCard): boolean {
  return card.status === "lost" || card.status === "frozen";
}

/** 一张卡的自我介绍(所有回复与列表统一用这一句) */
export function describeCard(card: BankCard): string {
  const kind = CARD_KIND_LABELS[card.kind];
  const status = CARD_STATUS_LABELS[card.status];
  const limit = card.creditLimit != null ? ` · 额度 ${fmtMoney(card.creditLimit)} 元` : "";
  return `${card.productName}(${kind} 尾号 ${card.last4})· ${status}${limit}`;
}

/**
 * 卡片列表渲染。
 *
 * ★ 与理财列表同一条交互原则:**给出编号**与**接住编号**必须成套提供。
 *   列表里带上序号,后面的位置指代才有落点。
 */
export function renderCardList(cards: BankCard[], now?: number): string[] {
  const lines: string[] = [];
  for (const [i, c] of cards.entries()) {
    lines.push(`${i + 1}. ${c.productName}(${CARD_KIND_LABELS[c.kind]}) 尾号 ${c.last4}`);
    lines.push(`   状态:${CARD_STATUS_LABELS[c.status]}${c.activated ? "" : " · 尚未激活,暂不能使用"}`);
    if (c.creditLimit != null) {
      lines.push(
        `   额度:${fmtMoney(c.creditLimit)} 元 · 已用 ${fmtMoney(c.usedAmount ?? 0)} 元 · 可用 ${fmtMoney(c.availableLimit ?? 0)} 元`,
      );
    } else {
      lines.push("   类型:借记卡,无授信额度");
    }
    lines.push(
      `   有效期至 ${fmtMonth(c.expiresAt)} · 开卡 ${fmtDay(c.openedAt)}${now != null ? `(已用卡 ${monthsBetween(c.openedAt, now)} 个月)` : ""}`,
    );
    if (c.restriction) {
      lines.push(`   交易限制:${c.restriction.causeLabel}。${c.restriction.detail}`);
    }
    if (c.status === "pending_activation") {
      lines.push("   新卡须激活并设置交易密码后方可使用。如需办理,请回复「激活尾号 " + c.last4 + "」。");
    }
    lines.push("");
  }
  return lines;
}

// ============================================================================
// 三、额度调整资格判定(★ 行业规则 1 的落地)
// ============================================================================

export type LimitEligibilityStatus =
  /** 符合申请条件 */
  | "eligible"
  /** 用卡时间不足 */
  | "too_new"
  /** 距上次调额不足冷却期 */
  | "cooling_down"
  /** 该卡没有授信额度(借记卡/虚拟卡) */
  | "no_credit_line"
  /** 卡片当前不可用(挂失/冻结/未激活) */
  | "card_not_usable";

export interface LimitEligibility {
  status: LimitEligibilityStatus;
  /** 客户是否可以提交提额申请 */
  canApply: boolean;
  /** 当前额度 */
  currentLimit: number | null;
  /** 系统建议的可申请额度上限(可申请时才有值) */
  suggestedMaxLimit: number | null;
  /** 客户需要等待的月数(不满足时间条件时有值) */
  waitMonths: number;
  /** 面向客户的说明:为什么能/不能申请 */
  reason: string;
  /** ★ 我们帮你做的那一部分 */
  ourPart: string;
  /** ★ 银行审核说了算的那一部分 */
  bankPart: string;
}

/**
 * 额度调整资格判定。
 *
 * ★ 为什么把"资格"单独做成一个只读能力,而不是让用户直接提交申请再被拒:
 *   客户的问法常常是"额度太低能不能提额" —— 他问的是**资格**。
 *   如果直接走申请流程,他会莫名收到一张"申请已提交"的回执,
 *   而实际上他连自己够不够格都不知道。先答资格,再谈申请,是顺序问题。
 *
 * ★ `monthsBetween` 用整月口径(与银行"用卡满 6 个月"的说法一致),
 *   不做"180 天"这种近似 —— 客户按日期算,系统也必须按日期算。
 */
export function checkLimitEligibility(input: {
  card: BankCard;
  now: number;
}): LimitEligibility {
  const { card, now } = input;

  // 借记卡没有额度这回事 —— 必须说清,而不是回一句"暂不支持"
  if (card.creditLimit == null) {
    return {
      status: "no_credit_line",
      canApply: false,
      currentLimit: null,
      suggestedMaxLimit: null,
      waitMonths: 0,
      reason:
        `${card.productName}(尾号 ${card.last4})是${CARD_KIND_LABELS[card.kind]},` +
        "借记卡没有授信额度这回事 —— 卡里能花多少取决于余额,不存在「提额」流程。",
      ourPart: "如果您的诉求是「刷卡额度不够用」,我可以帮您看看是不是可以调高转账/消费限额,或者申请一张信用卡。",
      bankPart: "信用卡的授信额度由银行审批,不能通过借记卡「提升」。",
    };
  }

  // 挂失/冻结/未激活的卡,先解决可用性,再谈额度
  if (isCardBlocked(card.status)) {
    return {
      status: "card_not_usable",
      canApply: false,
      currentLimit: card.creditLimit,
      suggestedMaxLimit: null,
      waitMonths: 0,
      reason:
        `这张卡当前状态是「${CARD_STATUS_LABELS[card.status]}」,` +
        "在卡片恢复可用之前,提额申请不会被受理 —— 银行无法给一张已冻结的卡审批新额度。",
      ourPart: card.status === "pending_activation"
        ? "我先帮您把卡激活,激活之后就能谈额度了。"
        : "我先帮您处理卡片状态问题,处理完再回来提额。",
      bankPart: "额度审批只能在卡片状态正常的卡上进行。",
    };
  }

  const monthsOpen = monthsBetween(card.openedAt, now);
  if (monthsOpen < LIMIT_RULES.minMonthsSinceOpen) {
    const wait = LIMIT_RULES.minMonthsSinceOpen - monthsOpen;
    return {
      status: "too_new",
      canApply: false,
      currentLimit: card.creditLimit,
      suggestedMaxLimit: null,
      waitMonths: wait,
      reason:
        `您的这张卡开卡 ${monthsOpen} 个月,还没满 ${LIMIT_RULES.minMonthsSinceOpen} 个月。` +
        `按银行现行规则,新开户或刚调额不久的客户需要**用卡满 ${LIMIT_RULES.minMonthsSinceOpen} 个月左右**再申请提额 ——` +
        `还差约 ${wait} 个月。`,
      ourPart: "我可以先帮您记下提额意向,到时间提醒您;也可以先帮您看看临时额度或分期方案。",
      bankPart: `用卡满 ${LIMIT_RULES.minMonthsSinceOpen} 个月是银行的受理门槛,不是我们卡您 —— 提交上去也会被退回。`,
    };
  }

  if (card.lastLimitAdjustmentAt != null) {
    const monthsSinceAdj = monthsBetween(card.lastLimitAdjustmentAt, now);
    if (monthsSinceAdj < LIMIT_RULES.minMonthsSinceAdjustment) {
      const wait = LIMIT_RULES.minMonthsSinceAdjustment - monthsSinceAdj;
      return {
        status: "cooling_down",
        canApply: false,
        currentLimit: card.creditLimit,
        suggestedMaxLimit: null,
        waitMonths: wait,
        reason:
          `您上次调额是在 ${fmtDay(card.lastLimitAdjustmentAt)}(约 ${monthsSinceAdj} 个月前),` +
          `距上次调整不满 ${LIMIT_RULES.minMonthsSinceAdjustment} 个月。频繁提额会被风控视为异常用卡行为,` +
          `需要再等约 ${wait} 个月。`,
        ourPart: "我可以帮您记下意向并设置提醒,冷却期一满就提醒您提交。",
        bankPart: `调额冷却期是银行风控规则,${LIMIT_RULES.minMonthsSinceAdjustment} 个月内重复申请不会受理。`,
      };
    }
  }

  // 可申请:给出建议额度上限(当前额度 × (1 + 上限比例),再受风控封顶)
  const capByRatio = Math.floor((card.creditLimit * (1 + LIMIT_RULES.maxIncreaseRatio)) / 1000) * 1000;
  const suggested = Math.min(capByRatio, LIMIT_RULES.maxResultingLimit);

  return {
    status: "eligible",
    canApply: true,
    currentLimit: card.creditLimit,
    suggestedMaxLimit: suggested,
    waitMonths: 0,
    reason:
      `您的卡已用卡 ${monthsOpen} 个月,距上次调额超过 ${LIMIT_RULES.minMonthsSinceAdjustment} 个月,符合提额申请条件。` +
      `当前额度 ${fmtMoney(card.creditLimit)} 元,单次可申请的额度上限约 ${fmtMoney(suggested)} 元。`,
    ourPart: "我可以马上帮您提交提额申请,提交前会先把申请额度、审核时效和可能的结果说清楚,由您确认。",
    bankPart:
      `★ 提额不是即时生效:提交后进入银行审核(约 ${LIMIT_RULES.reviewBusinessDays} 个工作日),` +
      "审核通过才会生效,结果会通知您。我不能、也不会承诺一定批下来。",
  };
}

// ============================================================================
// 四、交易限制:原因分类与处理通道(★ 行业规则 2 的落地)
// ============================================================================

export interface RestrictionDiagnosis {
  card: BankCard;
  restriction: CardRestriction | null;
  /** 面向客户的诊断说明 */
  summary: string;
  /** 我们能不能受理解除申请 */
  ourPart: string;
  /** 银行/有权机关说了算的部分 */
  bankPart: string;
  /** 客户现在就该做的动作 */
  nextActions: string[];
}

/**
 * 交易限制诊断。
 *
 * ★ 这是本场景最重要的一条业务立场:**限制不能一刀切**。
 *   四种成因的处理方式完全不同:
 *
 *     | 成因             | 谁说了算                     | 能不能"帮你解" |
 *     |------------------|------------------------------|----------------|
 *     | 异常交易         | 银行风控审核                 | 可提交申请     |
 *     | 信息不完整       | 客户自己补齐(需人脸/证件)   | 不能代理,引导  |
 *     | 司法冻结         | 有权机关                     | 一律不能解     |
 *     | 安全风险         | 银行安全团队(多为核实身份)  | 可提交申请     |
 *
 *   把司法冻结说成"我帮你提交解除申请",是本场景最严重的一类错误:
 *   它既给了客户不可能兑现的承诺,又让银行承担了"试图绕开司法冻结"的观感。
 *   因此 `judicial_freeze` 在**能力层**就直接拒收(见 registry 的 card.unblock),
 *   而不是靠提示词叮嘱模型别说错。
 */
export function diagnoseRestriction(card: BankCard, now: number): RestrictionDiagnosis {
  const r = card.restriction;

  if (!r) {
    return {
      card,
      restriction: null,
      summary: `这张卡(尾号 ${card.last4})当前没有交易限制,状态是「${CARD_STATUS_LABELS[card.status]}」。`,
      ourPart: "如果您遇到了刷不过、交易被拒的情况,可能是单笔限额、商户类别限制或余额问题,我可以帮您逐项排查。",
      bankPart: "如确有交易失败,以银行侧返回的拒付原因码为准。",
      nextActions: ["如果确实有交易失败,把失败时间和金额告诉我,我来帮您查具体原因"],
    };
  }

  const base = {
    card,
    restriction: r,
    bankPart: "",
  };

  switch (r.cause) {
    case "abnormal_transaction":
      return {
        ...base,
        summary:
          `查到限制原因:**异常交易**。${r.detail}\n` +
          `限制开始时间:${fmtDay(r.since)}(已 ${daysBetween(r.since, now)} 天)。`,
        ourPart: "我可以帮您提交**解除限制申请**,并附上您的说明,由银行风控审核。申请提交后由银行决定是否解除。",
        bankPart: "★ 是否解除由银行风控审核决定,不是我能承诺的;审核期间限制仍然生效。",
        nextActions: [
          "准备好能说明交易真实性的材料(消费凭证、订单截图)",
          "回复「提交解除限制申请」,我会带上您的说明一起提交",
        ],
      };

    case "incomplete_information":
      return {
        ...base,
        summary:
          `查到限制原因:**信息不完整**。${r.detail}\n` +
          `限制开始时间:${fmtDay(r.since)}(已 ${daysBetween(r.since, now)} 天)。`,
        ourPart:
          "这一类**不能在对话里代办** —— 补充身份信息需要通过人脸识别与证件上传,只能在 App 的安全流程里完成。",
        bankPart: "补齐信息后限制通常会自动解除,不需要额外申请。",
        nextActions: [
          "打开 App「我的 → 身份信息」按提示补全证件有效期与地址",
          "材料提交后一般 1 个工作日内自动解除",
        ],
      };

    case "judicial_freeze":
      return {
        ...base,
        summary:
          `查到限制原因:**司法冻结**。${r.detail}\n` +
          `冻结开始时间:${fmtDay(r.since)}(已 ${daysBetween(r.since, now)} 天)。`,
        ourPart:
          "这一类**我无法受理解除申请**,银行也无权自行解除 —— 我没有把它提交上去,因为提交了也不会有结果。",
        bankPart:
          "★ 司法冻结只能凭有权机关(法院/公安等)出具的解除冻结通知书办理解除。" +
          "请联系出具冻结的机关了解案情与解除条件。",
        nextActions: [
          `联系出具冻结的机关(冻结文书号见 App「卡片详情 → 限制说明」)`,
          "拿到解除冻结通知书后,到任一网点或通过客服提交,银行在收到文书后办理解除",
        ],
      };

    case "security_risk":
      return {
        ...base,
        summary:
          `查到限制原因:**安全风险**。${r.detail}\n` +
          `限制开始时间:${fmtDay(r.since)}(已 ${daysBetween(r.since, now)} 天)。`,
        ourPart: "我可以帮您提交解除限制申请,银行安全团队会核实身份与用卡情况。",
        bankPart: "★ 是否解除由银行安全团队决定;可能需要您配合完成人脸识别或到网点核实。",
        nextActions: [
          "先确认近期是否有异地/陌生设备登录",
          "回复「提交解除限制申请」,我会带上您的说明一起提交",
        ],
      };

    case "self_setting":
      return {
        ...base,
        summary:
          `查到限制原因:**客户自设限额**。${r.detail}\n` +
          `设置时间:${fmtDay(r.since)}。`,
        ourPart:
          "这是您自己设的限制(单笔/单日限额或境外交易开关)。关闭它属于**放宽风险敞口**的方向," +
          "按我们的分级原则必须由您本人确认,我不会自动替您打开。",
        bankPart: "自设限额随时可以修改,修改后立即生效。",
        nextActions: ["回复「我要调整自设限额」,我会先展示当前设置再让您确认"],
      };
  }
}

/** 该限制是否可以在本渠道受理解除申请 */
export function canSubmitUnblock(r: CardRestriction | null): boolean {
  return r != null && r.channel === "agent_application";
}

/** 按原因给出处理通道(银行核心侧也用它,保证两侧口径一致) */
export function restrictionChannelFor(cause: RestrictionCause): RestrictionChannel {
  switch (cause) {
    case "judicial_freeze":
      return "authority_document_only";
    case "incomplete_information":
      return "native_self_service";
    default:
      return "agent_application";
  }
}

// ============================================================================
// 五、挂失与补卡(★ 行业规则 3、4 的落地)
// ============================================================================

/**
 * 补卡方案对比。
 *
 * ★ 这张表必须在**操作之前**给客户看。
 *   换号与保号的差别不只是"等多久",而是三件事同时变化:
 *
 *     | 方案     | 卡号       | 到手时间 | 激活 | 交易密码   | 已绑业务           |
 *     |----------|-----------|---------|------|-----------|--------------------|
 *     | 换号补卡 | 变         | 约 5 天  | 需要 | 需重新设置 | 需重新绑定         |
 *     | 保留原号 | 不变       | 约 12 天 | 需要 | 沿用原密码 | 无需重绑           |
 *
 *   "保留原号需等待更长时间"这一条,客户在选之前必须知道 ——
 *   否则他选了保号,等第 6 天没收到卡就会来投诉"你们说 5 天"。
 */
export interface ReplacementOption {
  mode: "new_number" | "keep_number";
  modeLabel: string;
  /** 预计到手时间 */
  estimatedArrivalAt: number;
  estimatedDays: number;
  /** 卡号是否变化 */
  cardNumberChanges: boolean;
  newCardLast4: string | null;
  /** 是否需要激活 */
  requiresActivation: boolean;
  /** 是否需要重新设置交易密码 */
  requiresTransactionPassword: boolean;
  /** 已绑定的快捷支付/代扣是否需要重新绑定 */
  requiresRebind: boolean;
  /** 该方案的代价与适用情形 */
  tradeoff: string;
  /** 面向客户的完整说明 */
  wording: string;
}

/**
 * 构造两种补卡方案。
 *
 * ★ 纯函数 + 固定 ETA:同一个客户问两次,拿到的天数必须一样。
 *   "补卡要几天"是客诉高发问题,系统自己前后不一致会直接摧毁信任。
 */
export function buildReplacementOptions(input: {
  card: BankCard;
  now: number;
  /** 用于生成新卡尾号:由银行核心提供确定性序列,不由能力层编造 */
  newCardLast4: string;
}): ReplacementOption[] {
  const { card, now, newCardLast4 } = input;
  const day = 24 * 3600 * 1000;

  const newNumber: ReplacementOption = {
    mode: "new_number",
    modeLabel: "换号补卡(新卡号)",
    estimatedArrivalAt: now + REPLACEMENT_ETA_DAYS.newNumber * day,
    estimatedDays: REPLACEMENT_ETA_DAYS.newNumber,
    cardNumberChanges: true,
    newCardLast4,
    requiresActivation: true,
    requiresTransactionPassword: true,
    requiresRebind: true,
    tradeoff: "到手快,但卡号会变,已绑的快捷支付、代扣、订阅都需要重新绑定;交易密码要重新设置。",
    wording: "",
  };
  newNumber.wording =
    `换号补卡:新卡尾号 ${newCardLast4},预计 ${REPLACEMENT_ETA_DAYS.newNumber} 个工作日到手。` +
    "到手后需要① 激活,② 重新设置交易密码 —— 因为卡号变了,原交易密码不会沿用到新卡上。" +
    "原卡已绑定的快捷支付、自动扣款、会员订阅都要重新绑定。";

  const keepNumber: ReplacementOption = {
    mode: "keep_number",
    modeLabel: "保留原号补卡",
    estimatedArrivalAt: now + REPLACEMENT_ETA_DAYS.keepNumber * day,
    estimatedDays: REPLACEMENT_ETA_DAYS.keepNumber,
    cardNumberChanges: false,
    newCardLast4: null,
    requiresActivation: true,
    requiresTransactionPassword: false,
    requiresRebind: false,
    tradeoff: "卡号不变、不用重绑,但**等待时间明显更长**(需要重新制卡并做卡号迁移),而且必须激活后才能用。",
    wording: "",
  };
  keepNumber.wording =
    `保留原号补卡:卡号仍是尾号 ${card.last4},预计 ${REPLACEMENT_ETA_DAYS.keepNumber} 个工作日到手。` +
    "★ 比换号补卡**多等约 " +
    (REPLACEMENT_ETA_DAYS.keepNumber - REPLACEMENT_ETA_DAYS.newNumber) +
    " 天** —— 这是保留原号的代价,请在选择前确认您愿意等。" +
    "到手后需要激活,交易密码沿用原密码,已绑定的快捷支付与代扣无需重新绑定。";

  return [newNumber, keepNumber];
}

/**
 * 新卡到手后的动作清单。
 *
 * ★ 需求里给的三条差异,在这里被落成一张**可执行的清单**:
 *
 *     | 情形              | 激活 | 设置交易密码       |
 *     |-------------------|------|--------------------|
 *     | 挂失换卡(换号)   | 需要 | 需要(重新设置)     |
 *     | 挂失换卡(保号)   | 需要 | 不需要(沿用原密码) |
 *     | 新开户 / 新办卡   | 需要 | 需要(新设)         |
 *     | 到期换卡          | 需要 | 不需要(沿用原密码) |
 *     | 损坏换卡          | 需要 | 不需要(沿用原密码) |
 *
 *   "激活"是所有情形都要做的 —— 因为新卡从未被使用过;
 *   "设置交易密码"只在**卡号变化或首次开户**时才需要 ——
 *   因为交易密码是绑在卡号上的。
 */
export type CardChangeScenario =
  | "loss_new_number"
  | "loss_keep_number"
  | "new_application"
  | "renewal_expired"
  | "renewal_damaged";

export interface PostDeliveryRequirement {
  scenario: CardChangeScenario;
  scenarioLabel: string;
  requiresActivation: boolean;
  requiresTransactionPassword: boolean;
  /** 交易密码是沿用原密码还是新设 */
  passwordMode: "inherit" | "reset" | "none";
  passwordModeLabel: string;
  /** 是否需要在激活时重新设置(与 requiresTransactionPassword 同义,保留可读性) */
  summary: string;
}

export const POST_DELIVERY_REQUIREMENTS: Record<CardChangeScenario, PostDeliveryRequirement> = {
  loss_new_number: {
    scenario: "loss_new_number",
    scenarioLabel: "挂失换卡(换号)",
    requiresActivation: true,
    requiresTransactionPassword: true,
    passwordMode: "reset",
    passwordModeLabel: "需重新设置交易密码",
    summary: "新卡到手后:① 激活;② 重新设置交易密码(卡号变了,原密码不沿用)。",
  },
  loss_keep_number: {
    scenario: "loss_keep_number",
    scenarioLabel: "挂失换卡(保留原号)",
    requiresActivation: true,
    requiresTransactionPassword: false,
    passwordMode: "inherit",
    passwordModeLabel: "交易密码沿用原密码",
    summary: "新卡到手后:激活即可,交易密码沿用原密码,无需重新设置。",
  },
  new_application: {
    scenario: "new_application",
    scenarioLabel: "新开户 / 新办卡",
    requiresActivation: true,
    requiresTransactionPassword: true,
    passwordMode: "reset",
    passwordModeLabel: "需新设交易密码",
    summary: "新卡到手后:① 激活;② 设置交易密码(新开户必须新设)。",
  },
  renewal_expired: {
    scenario: "renewal_expired",
    scenarioLabel: "到期换卡",
    requiresActivation: true,
    requiresTransactionPassword: false,
    passwordMode: "inherit",
    passwordModeLabel: "交易密码沿用原密码",
    summary: "新卡到手后:只需激活,交易密码沿用原密码。",
  },
  renewal_damaged: {
    scenario: "renewal_damaged",
    scenarioLabel: "损坏换卡",
    requiresActivation: true,
    requiresTransactionPassword: false,
    passwordMode: "inherit",
    passwordModeLabel: "交易密码沿用原密码",
    summary: "新卡到手后:只需激活,交易密码沿用原密码。",
  },
};

export function requirementForScenario(scenario: CardChangeScenario): PostDeliveryRequirement {
  return POST_DELIVERY_REQUIREMENTS[scenario];
}

/** 由补卡模式反推场景,避免两处各写一遍映射 */
export function scenarioForReplacementMode(mode: "new_number" | "keep_number"): CardChangeScenario {
  return mode === "keep_number" ? "loss_keep_number" : "loss_new_number";
}

/**
 * 由卡片自身的补发关系判定激活场景。
 *
 * ★ 银行核心侧用 `replacementOf` 表达补发关系,约定为三种取值:
 *     · null            —— 不是补发卡(新开户 / 首次发卡)
 *     · 等于自身 cardId —— 保留原号的补发卡
 *     · 其他字符串       —— 换号的补发卡
 *   这个判定的唯一用途是回答"激活之后还要不要重设交易密码",
 *   因此必须只有一处实现 —— 两处各写一遍,迟早会出现
 *   "激活卡上说要重设密码、激活回执里说沿用原密码"这种自相矛盾。
 */
export function scenarioForActivation(input: {
  replacementOf: string | null;
  cardId: string;
  status: CardStatus;
}): CardChangeScenario {
  const isReplacement = input.replacementOf != null || input.status === "replacement_in_transit";
  if (!isReplacement) return "new_application";
  return input.replacementOf === input.cardId ? "loss_keep_number" : "loss_new_number";
}

// ============================================================================
// 六、极高风险操作:Agent 不代理(★ 行业规则 5 的落地)
// ============================================================================

/**
 * 不可代理的凭证变更操作。
 *
 * ★ 这一类操作之所以"极高风险",不是因为它金额大(它根本不涉及金额),
 *   而是因为它**改变的是"谁能代表客户"这件事**:
 *   改绑手机号 = 抢走短信验证码的接收方;改交易密码 = 拿走交易的最终凭证。
 *   账户接管的完整路径通常是:改手机号 → 收验证码 → 改密码 → 转走钱。
 *
 *   因此这两件事在本项目里的处理是:能力层直接 `baseTier: "blocked"`,
 *   策略引擎硬规则 `R-CARD-CREDENTIAL-CHANGE-BLOCKED` 命中即 deny,
 *   Agent 只做**引导**,并在审计里留下 `card_credential_change_blocked`。
 *
 *   ★ 注意这里连"帮用户发起申请"都不做 —— 与司法冻结一样,
 *     不是一个"我们提交、银行审核"的事情,而是**根本不该经过对话通道**的事情。
 */
export interface ForbiddenDelegation {
  id: string;
  /** 匹配用户话语的模式 */
  re: RegExp;
  label: string;
  /** 极高风险的原因(讲给用户听) */
  why: string;
  /** 在哪里能做 */
  where: string;
  /** 原生流程要点 */
  nativeSteps: string[];
}

export const FORBIDDEN_DELEGATIONS: ForbiddenDelegation[] = [
  {
    id: "change_phone",
    re: /(改|换|变更|修改|绑定|解绑|改绑).{0,6}(手机号|手机|号码|电话)|(手机号|号码).{0,4}(改|换|变更|绑定|解绑)/,
    label: "修改绑定手机号",
    why:
      "改绑手机号等于改变「谁能收到您的验证码」。账户接管最常见的路径就是:先改手机号拿到验证码," +
      "再改密码,最后转走资金。所以这一步一旦被代理,后面所有验证都形同虚设。",
    where: "App →「我的 → 安全中心 → 手机号管理」",
    nativeSteps: [
      "需要用**原手机号**接收验证码验证",
      "再完成一次人脸识别",
      "部分情况需要等待 24 小时生效(给真正的卡主留出反悔窗口)",
    ],
  },
  {
    id: "change_password",
    re: /(改|换|修改|重置|忘记).{0,6}(交易密码|支付密码|登录密码|密码|pin)|(密码).{0,4}(改|换|重置|忘记)/i,
    label: "修改 / 重置密码",
    why:
      "密码是客户本人的最终交易凭证。Agent 既不接触密码,也不具备证明「屏幕对面就是卡主本人」的能力 ——" +
      "让我来改,等于把身份验证这一步交给了对话通道。",
    where: "App →「我的 → 安全中心 → 密码管理」",
    nativeSteps: [
      "登录密码:验证原密码或短信验证码后自行修改",
      "交易密码:需人脸识别 + 原交易密码,或到网点办理重置",
      "连续输错会被锁定,锁定后需到网点解锁",
    ],
  },
  {
    id: "reset_transaction_password",
    re: /(重置|重设|忘了|忘记|不记得).{0,4}(交易密码|支付密码)|(交易密码|支付密码).{0,4}(忘了|忘记|不记得|锁定|冻结)/,
    label: "重置交易密码",
    why: "重置交易密码需要证明「您是卡主本人」,这个证明只能由原生安全环境给出,对话做不到。",
    where: "App →「我的 → 安全中心 → 交易密码 → 忘记交易密码」",
    nativeSteps: ["人脸识别 + 证件核验", "或持本人身份证到任一网点办理"],
  },
];

/** 识别用户是否在要求一件极高风险、不可代理的事 */
export function detectForbiddenDelegation(text: string): ForbiddenDelegation | null {
  for (const d of FORBIDDEN_DELEGATIONS) {
    if (d.re.test(text)) return d;
  }
  return null;
}

// ============================================================================
// 七、口径拆分:我们帮你做 vs 银行审核说了算(★ 贯穿全场景的表达纪律)
// ============================================================================

/**
 * 三段式口径。
 *
 * ★ 需求里点得最明确的一条:
 *   「调额申请提交后不能说已经帮你提到五万,只能说申请已提交、审核结果会通知」。
 *
 *   这条纪律的通用形式是:**任何一个动作,都要说清哪部分是已完成的,
 *   哪部分还悬在别人手里**。因此本文件把它做成结构(ourPart / bankPart),
 *   而不是在文案里顺手写一句 —— 结构能被测试锁住,文案不能。
 */
export interface SplitWording {
  /** 已经/马上完成的部分(我们做的) */
  ourPart: string;
  /** 尚未生效、由银行或有权机关决定的部分 */
  bankPart: string;
  /** 现在的状态(必须如实:申请已提交 ≠ 已提额) */
  currentState: string;
}

/** 金额调整类动作的口径 */
export function limitApplicationWording(input: {
  cardLast4: string;
  requestedLimit: number;
  currentLimit: number;
  estimatedDecisionAt: number;
}): SplitWording {
  return {
    ourPart: `我已经把您的提额申请提交上去了(尾号 ${input.cardLast4},目标额度 ${fmtMoney(input.requestedLimit)} 元)。`,
    bankPart: `★ 提额不是即时生效:接下来由银行审核,预计 ${fmtDay(input.estimatedDecisionAt)} 前出结果。审核通过后额度才会变成 ${fmtMoney(input.requestedLimit)} 元;也可能只批一部分,或者不批。`,
    currentState: `您当前的额度仍然是 ${fmtMoney(input.currentLimit)} 元 —— 申请已提交,额度还没有变化。`,
  };
}

// ============================================================================
// 八、工具
// ============================================================================

/** 整数月数差(与银行"用卡满 N 个月"的口径一致,不做 30 天近似) */
export function monthsBetween(from: number, to: number): number {
  const a = new Date(from);
  const b = new Date(to);
  let months = (b.getFullYear() - a.getFullYear()) * 12 + (b.getMonth() - a.getMonth());
  if (b.getDate() < a.getDate()) months -= 1;
  return Math.max(0, months);
}

export function daysBetween(from: number, to: number): number {
  return Math.max(0, Math.floor((to - from) / (24 * 3600 * 1000)));
}

export function fmtMonth(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

/**
 * ★ `fmtDay` / `fmtMoney` 已收归 `util/format.ts`(原来与 wealth.ts 各有一份逐字相同的拷贝)。
 *   同名 re-export,调用方导入路径不变;本文件内部使用走 import。
 */
export { fmtDay, fmtMoney } from "../util/format.ts";
import { fmtDay, fmtMoney } from "../util/format.ts";

/** 尾号指认:用户最常说「尾号 1234 那张」 */
export function matchCardByLast4(cards: BankCard[], text: string): BankCard | null {
  const m = text.match(/(?:尾号|后四位|末四位|最后四位|\*{2,}\s*)\s*(\d{4})/);
  if (m?.[1]) {
    const hit = cards.find((c) => c.last4 === m[1]);
    return hit ?? null;
  }
  // 裸四位数字:只在唯一命中时采信,多张卡命中一律不猜
  const bare = text.match(/(?<!\d)(\d{4})(?!\d)/);
  if (bare?.[1]) {
    const hits = cards.filter((c) => c.last4 === bare[1]);
    if (hits.length === 1) return hits[0]!;
  }
  return null;
}

/** 卡种口语指认:"信用卡""储蓄卡/借记卡""虚拟卡" */
export function matchCardByKindHint(cards: BankCard[], text: string): BankCard | null {
  const wantsCredit = /(信用卡|贷记卡|透支卡)/.test(text);
  const wantsDebit = /(借记卡|储蓄卡|工资卡|借记)/.test(text);
  const wantsVirtual = /虚拟卡/.test(text);
  if (!wantsCredit && !wantsDebit && !wantsVirtual) return null;
  const pool = cards.filter((c) =>
    wantsCredit ? c.kind === "credit" : wantsDebit ? c.kind === "debit" : c.kind === "virtual",
  );
  return pool.length === 1 ? pool[0]! : null;
}

/** 按卡组织/产品名中的关键词指认,如「白金卡」 */
export function matchCardByNameHint(cards: BankCard[], text: string): BankCard | null {
  const hits = cards.filter((c) => c.productName.length >= 3 && text.includes(c.productName));
  if (hits.length === 1) return hits[0]!;
  return null;
}
