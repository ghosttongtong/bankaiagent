/**
 * 业务态口径(八档)—— 一个纯函数,三处共用。
 *
 * ★ 为什么值得独立成一个模块:
 *   同一件事会在三个地方被描述 —— ① 对话里的回复、② 首页「历史业务」列表、
 *   ③ 历史会话详情页。如果每处各写一套文案,迟早出现"对话说已提交、列表说已办结"
 *   这种自相矛盾,而客户只会相信他先看到的那一句。
 *   状态因此由**同一个纯函数**算出来:口径不可能不一致,因为它只有一处。
 *
 * ★ 一条铁律(客户点名要求):**即时生效**与**已提交待审**必须分开。
 *   · 挂失是即时生效的 —— 冻结此刻已经发生;
 *   · 提额 / 补卡 / 解冻 / 办新卡 / 申购 / 赎回都是"已提交,等银行审核或等 T+N"。
 *   把后者写成「已办结」,等于暗示客户"额度已经提了""钱已经到账了"。
 *   这不是措辞问题,而是把"申请"读成了"结果"。
 *
 * ★ 状态来源只用真实字段(能力返回值 / 策略裁决),不猜文案:
 *   本模块不认识"模型说了什么",只认识"能力返回了什么、裁决判了什么"。
 */

import { fmtDay, fmtYuan } from "../util/format.ts";

/** 八档业务态。顺序不代表优先级(优先级见 OPERATION_STATUS_PRIORITY) */
export type OperationStatus =
  /** 已拦截:不可代办 / 超出代理范围 */
  | "blocked"
  /** 已转人工审批 */
  | "handoff"
  /** 已取消(客户或系统) */
  | "cancelled"
  /** 办理失败 */
  | "failed"
  /** 已提交,待银行审核 / 已受理(T+N 确认) */
  | "submitted"
  /** 已办结(即时生效) */
  | "done"
  /** 待客户确认 / 待验证 */
  | "pending"
  /** 仅咨询(只读问答) */
  | "inquiry";

/** 界面色调。前端只按 tone 上色,不自己判断状态 —— 前端零业务判断 */
export type OperationTone = "ok" | "info" | "warn" | "bad" | "muted";

export const OPERATION_STATUS_TONE: Record<OperationStatus, OperationTone> = {
  blocked: "bad",
  handoff: "warn",
  cancelled: "muted",
  failed: "bad",
  submitted: "info",
  done: "ok",
  pending: "warn",
  inquiry: "muted",
};

/**
 * 会话级状态怎么取(31 文档 §4.3):一个会话可能有多笔操作,
 * 取**最需要关注**的那一个。顺序:blocked > handoff > failed > pending >
 * submitted > cancelled > done > inquiry。
 *
 * ★ 为什么 blocked 排第一:它代表"客户想办但没办成,而且是被拦下的" ——
 *   这是最需要客户看见并处理的一种状态,不能因为后面还办成了一笔查询就被盖住。
 */
export const OPERATION_STATUS_PRIORITY: OperationStatus[] = [
  "blocked",
  "handoff",
  "failed",
  "pending",
  "submitted",
  "cancelled",
  "done",
  "inquiry",
];

/**
 * 语义固定为"已提交待审"的能力。
 *
 * ★ 注意这些能力**执行成功**(ok=true)也不等于办结:
 *   提额通过审核前额度不会变,补卡要等制卡寄送,申购份额要 T+1 确认。
 *   即使某天有人把能力实现改成"同步完成",这张表仍然是口径的唯一出处 ——
 *   改口径要改这里,而不是在各处文案里悄悄改。
 */
export const SUBMITTED_CAPABILITIES: ReadonlySet<string> = new Set([
  "card.limit_adjust",
  "card.unblock",
  "card.new_application",
  "card.replace",
  "wealth.purchase",
  "wealth.redeem",
  "collection.create",
]);

export interface OperationStatusInput {
  /** 能力名(如 transfer.submit) */
  capability: string;
  /** 能力执行结果;没执行(只展示了确认卡 / 被拦截)时为空 */
  outcome?: { ok: boolean; data?: unknown };
  /** 本轮终态。denied=被策略拦下;handoff=转人工 */
  terminal?: { kind: "denied" | "handoff" | "completed"; detail?: string };
  /** 还没确认时的干预级别:确认 / 强验证 */
  pendingTier?: "confirm" | "strong_auth";
  /** 是否只读能力。调用方有注册表时传真实值,没有则按能力名推断 */
  readOnly?: boolean;
  /** 被拦截时的首条规则说明 —— 让"为什么被拦"能落进台账 */
  denyReason?: string;
  /** 客户或系统放弃(取消确认) */
  cancelled?: boolean;
}

export interface OperationStatusInfo {
  status: OperationStatus;
  /** 面向客户的一句话口径 */
  label: string;
  /** 补充说明(流水号 / 目标额度 / 预计时效…),可选 */
  detail?: string;
  tone: OperationTone;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value != null && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/** 只读能力的名称兜底推断(调用方没有注册表时用) */
function looksReadOnly(capability: string): boolean {
  if (/^(account|payee)\./.test(capability)) return true;
  /**
   * ★ 订阅场景必须逐个数,不能用前缀兜底:
   *   `subscription.scan / list / detail` 是只读,而 `subscription.cancel`
   *   会改变合同关系 —— 用 `^subscription\.` 一把兜住,就会把"取消"
   *   标成"查询",台账上看起来什么都没发生。**前缀相同的动作,后果可以完全相反。**
   */
  if (/^subscription\.(scan|list|detail)$/.test(capability)) return true;
  /**
   * ★ 事件联动场景同样必须逐个数(与订阅同一条教训):
   *   `event.list` 与 `cross_scene_event_planning` 是只读(方案生成不改任何东西),
   *   而 `event.fund_step / event.external_step` 会改"这笔钱还能不能用"、
   *   甚至产生外部订单 —— 用 `^event\.` 一把兜住,就会把"下单"标成"查询"。
   */
  if (/^(event\.list|cross_scene_event_planning)$/.test(capability)) return true;
  return /\.(list|detail|compare|holdings|restrictions|eligibility|status|preview|list_products|list_schedules|list_balances|list_transactions)$/.test(
    capability,
  );
}

/** 带 ¥ 的金额 —— 与全仓口径共用一份实现(见 util/format.ts) */
const money = (n: number): string => fmtYuan(n);

/**
 * 能力专属口径。
 *
 * ★ 每一行都对应一个**真实字段**,不是按能力名硬编一句好话:
 *   · transfer.submit 读 data.status(已成功 / 处理中 / 已失败);
 *   · card.limit_adjust 读 data.statusLabel 与 data.requestedLimit;
 *   · wealth.redeem 读 data.settlement(到账时效)。
 *   能力没返回该字段时就不写那句 detail —— 宁可少一句,不可编一句。
 */
function capabilityStatus(capability: string, data: Record<string, unknown>): OperationStatusInfo | null {
  switch (capability) {
    case "transfer.submit": {
      const raw = str(data["status"]);
      const reference = str(data["reference"]);
      const detail = reference ? `流水号 ${reference}` : undefined;
      // ★ 处理中 / 已失败 都是能力**如实返回**的状态,不能一律写成"已转账成功"
      if (raw === "处理中") {
        return { status: "submitted", label: "处理中 · 待入账", ...(detail ? { detail } : {}), tone: "info" };
      }
      if (raw === "已失败") {
        return { status: "failed", label: "已失败", ...(detail ? { detail } : {}), tone: "bad" };
      }
      return { status: "done", label: "已转账成功", ...(detail ? { detail } : {}), tone: "ok" };
    }

    case "transfer.cancel": {
      const refund = num(data["refundAmount"]);
      return {
        status: "done",
        label: "已撤销",
        ...(refund != null ? { detail: `退回 ${money(refund)}` } : {}),
        tone: "ok",
      };
    }

    case "transfer.create_schedule": {
      const next = num(data["nextRunAt"]);
      return {
        status: "done",
        label: "定时任务已创建",
        ...(next != null ? { detail: `下次执行 ${fmtDay(next)}` } : {}),
        tone: "ok",
      };
    }

    case "transfer.cancel_schedule":
      // 取消定时任务是即时生效的:任务已经撤掉,不存在"待审核"
      return { status: "done", label: "定时任务已取消", tone: "ok" };

    case "card.report_loss": {
      // ★ 挂失是即时生效的:冻结已经发生,所以是 done,不是 submitted。
      const frozen = num(data["frozenCount"]);
      return {
        status: "done",
        label: "已挂失生效(立即冻结)",
        ...(frozen != null ? { detail: `已冻结 ${frozen} 张卡` } : {}),
        tone: "ok",
      };
    }

    case "card.replace": {
      const modeLabel = str(data["modeLabel"]);
      const days = num(data["estimatedDays"]);
      const detail = [modeLabel, days != null ? `预计 ${days} 个工作日` : undefined].filter(Boolean).join(" · ");
      return {
        status: "submitted",
        label: "补卡申请已受理",
        ...(detail ? { detail } : {}),
        tone: "info",
      };
    }

    case "card.activate": {
      // Agent 从不接触密码:这里只描述"该去设 / 可沿用",不能写成"密码已设置好"
      const passwordSet = data["transactionPasswordSet"] === true;
      return {
        status: "done",
        label: "已激活",
        detail: passwordSet ? "交易密码:待新设(已引导原生流程)" : "交易密码:沿用原密码",
        tone: "ok",
      };
    }

    case "card.limit_adjust": {
      const target = num(data["requestedLimit"]);
      return {
        status: "submitted",
        label: "提额申请已提交 · 待银行审核",
        ...(target != null ? { detail: `目标额度 ${money(target)}(额度审核通过前不变)` } : {}),
        tone: "info",
      };
    }

    case "card.unblock": {
      const cause = str(data["causeLabel"]);
      return {
        status: "submitted",
        label: "解除限制申请已提交 · 待银行审核",
        ...(cause ? { detail: `限制原因:${cause}` } : {}),
        tone: "info",
      };
    }

    case "card.new_application": {
      const kindLabel = str(data["kindLabel"]);
      return {
        status: "submitted",
        label: "办卡申请已提交 · 待审批",
        ...(kindLabel ? { detail: `卡种:${kindLabel}` } : {}),
        tone: "info",
      };
    }

    case "wealth.purchase": {
      const amount = num(data["amount"]);
      const shares = num(data["shares"]);
      const confirmedAt = num(data["sharesConfirmedAt"]);
      const parts = [
        amount != null ? `金额 ${money(amount)}` : undefined,
        shares != null ? `份额 ${shares}` : undefined,
        confirmedAt != null ? `份额 ${fmtDay(confirmedAt)} 确认` : "份额 T+1 确认",
      ];
      return {
        status: "submitted",
        label: "申购已受理 · 份额 T+1 确认",
        detail: parts.filter(Boolean).join(" · "),
        tone: "info",
      };
    }

    case "wealth.rollover_plan":
      return {
        status: "inquiry",
        label: "已生成到期续接方案 · 未申购",
        detail: "方案只比较,没有冻结资金",
        tone: "info",
      };

    case "wealth.rollover_choose": {
      const decision = str(data["status"]);
      if (decision === "declined") {
        return {
          status: "done",
          label: "已记录不续投 · 未申购",
          detail: "到期后按产品约定处理,没有冻结资金",
          tone: "ok",
        };
      }
      return {
        status: "pending",
        label: "已记下续接选择 · 到账前不会申购",
        detail: "资金回到活期后仍须另行确认申购",
        tone: "info",
      };
    }

    case "wealth.redeem": {
      const settlement = str(data["settlement"]);
      const arrival = num(data["estimatedArrivalAt"]);
      const detail = [settlement, arrival != null ? `${fmtDay(arrival)} 前后到账` : undefined]
        .filter(Boolean)
        .join(" · ");
      return {
        status: "submitted",
        label: "赎回已受理 · T+N 到账",
        ...(detail ? { detail } : {}),
        tone: "info",
      };
    }

    case "collection.create": {
      const total = num(data["totalAmount"]);
      return {
        status: "submitted",
        label: "已发起 AA 收款",
        ...(total != null ? { detail: `待收 ${money(total)}` } : {}),
        tone: "info",
      };
    }

    case "note.create": {
      const title = str(data["title"]);
      return {
        status: "done",
        label: "已记账",
        ...(title ? { detail: title } : {}),
        tone: "ok",
      };
    }

    // ---- 订阅代扣(新场景)----
    case "subscription.cancel": {
      /**
       * ★ 这一行的口径是本场景最要紧的一句话:
       *   取消**即时生效**(协议已解除、下次扣款计划已清空),所以是 done 而不是 submitted;
       *   但它**不是退款** —— 台账里必须把"本期已扣费用怎么处理"一起写出来,
       *   否则客户看到"已取消"就会以为钱会回来。
       *
       * ★ 还要照抄 refundPolicy 而不是自己总结:能力返回的是协议原文口径,
       *   编排器换个说法就变成了"系统对费用的另一种承诺"。
       */
      const merchant = str(data["merchantName"]);
      const refund = str(data["refundPolicy"]);
      const effective = str(data["effective"]);
      const nextAfter = data["nextDebitAtAfter"];
      const stillScheduled = nextAfter != null;
      const detail = [
        merchant,
        effective === "immediate" ? "已立即生效" : "下一期起不再扣款",
        refund,
        // ★ 取消成功却还留着下次扣款日 —— 这是必须暴露出来的异常,不能悄悄放过
        stillScheduled ? "★ 仍存在下次扣款计划,请核查" : undefined,
      ]
        .filter(Boolean)
        .join(" · ");
      return {
        status: "done",
        label: "已取消代扣协议 · 下一期不再扣款",
        ...(detail ? { detail } : {}),
        tone: "ok",
      };
    }

    case "subscription.scan": {
      const total = num(data["totalCount"]);
      const monthly = num(data["monthlyTotal"]);
      const cancelable = num(data["cancelableCount"]);
      const parts = [
        total != null ? `识别 ${total} 笔` : undefined,
        monthly != null ? `每月合计 ${money(monthly)}` : undefined,
        cancelable != null ? `其中 ${cancelable} 笔可在本行取消` : undefined,
      ];
      return {
        status: "inquiry",
        label: "已识别订阅代扣",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: "info",
      };
    }

    case "subscription.list": {
      const count = num(data["upcomingCount"]);
      const total = num(data["upcomingTotal"]);
      const parts = [
        count != null ? `${count} 笔即将扣款` : undefined,
        total != null ? `合计 ${money(total)}` : undefined,
      ];
      return {
        status: "inquiry",
        label: "已提示即将扣款的订阅",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: "info",
      };
    }

    case "subscription.detail": {
      const merchant = str(data["merchantName"]);
      const amount = num(data["amount"]);
      const parts = [merchant, amount != null ? `每期 ${money(amount)}` : undefined];
      return {
        status: "inquiry",
        label: "已查询订阅详情",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: "info",
      };
    }

    // ---- 跨场景事件联动(新场景)----
    case "event.list": {
      const triggers = num(data["triggerCount"]);
      const events = num(data["eventCount"]);
      const parts = [
        triggers != null ? `${triggers} 个触发器` : undefined,
        events != null ? `${events} 个已登记事件` : undefined,
      ];
      return {
        status: "inquiry",
        label: "已列出关键事件与触发器",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: "info",
      };
    }

    /**
     * ★ 方案生成的业务态刻意是 **pending(待客户确认)**,不是 done。
     *
     *   这是本场景最容易写错的一行:方案生成"成功"了,能力也确实 ok:true,
     *   但客户要办的事**一件都还没办** —— 它在等客户逐步确认。
     *   若标成"已办结",台账上就会显示"纪念日规划 · 已办结",
     *   而客户到了那天会发现礼物没订、钱也没预留。
     *   ★ 判据用的是能力返回的**步骤数与待确认金额**,不是文案。
     */
    case "cross_scene_event_planning": {
      const fundTotal = num(data["fundTotal"]);
      const externalTotal = num(data["externalTotal"]);
      const days = num(data["daysUntil"]);
      const steps = num(data["stepCount"]);
      const parts = [
        days != null ? `${days} 天后` : undefined,
        steps != null ? `${steps} 步方案` : undefined,
        fundTotal != null ? `资金操作 ${money(fundTotal)}` : undefined,
        externalTotal != null ? `外部服务 ${money(externalTotal)}` : undefined,
      ];
      const hasExecutable =
        (fundTotal != null && fundTotal > 0) || (externalTotal != null && externalTotal > 0);
      return {
        status: hasExecutable ? "pending" : "inquiry",
        label: hasExecutable ? "已生成联动方案 · 待您逐步确认" : "已生成联动方案(无需资金操作)",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: hasExecutable ? "warn" : "info",
      };
    }

    case "event.register": {
      const title = str(data["title"]);
      const statusLabel = str(data["kindLabel"]);
      const parts = [title, statusLabel];
      return {
        status: "done",
        label: "已登记关键事件",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: "ok",
      };
    }

    /**
     * ★ 资金操作的业务态是 done(即时生效),但 detail 必须写清"钱没有出去"。
     *   这一行与订阅取消的口径同源:状态词说的是"这一步办完了",
     *   而 detail 说的是"办完的是什么" —— 少了后者,客户会以为钱被划走了。
     */
    case "event.fund_step": {
      const modeLabel = str(data["modeLabel"]) ?? "";
      const toName = str(data["toName"]);
      const amount = num(data["amount"]);
      const availableAfter = num(data["availableAfter"]);
      const isSchedule = /定时/.test(modeLabel);
      const released = /解除/.test(modeLabel);
      const parts = [
        released ? "已回到可用余额" : isSchedule ? "已登记定时任务(到点执行)" : "已在本账户内预留(未对外支付)",
        toName,
        amount != null ? money(amount) : undefined,
        availableAfter != null ? `可用余额 ${money(availableAfter)}` : undefined,
      ];
      return {
        status: "done",
        label: released ? "已解除预留" : isSchedule ? "已登记定时任务" : "已预留资金 · 未对外支付",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: "ok",
      };
    }

    /**
     * ★ 外部订单一律是 **submitted(已受理)**,绝不是 done。
     *   商户有没有真的接单、档期能不能排上,银行侧不知道 ——
     *   写"已完成"就是把"提交"读成了"结果",而这正是本场景最不能犯的错:
     *   客户会按"已经订好了"去安排纪念日。
     *   detail 里同时带上退订政策:它是客户判断反悔成本的唯一依据。
     */
    case "event.external_step": {
      const merchant = str(data["merchantName"]);
      const item = str(data["item"]);
      const amount = num(data["amount"]);
      const cancelPolicy = str(data["cancelPolicy"]);
      const parts = [merchant, item, amount != null ? money(amount) : undefined, cancelPolicy];
      return {
        status: "submitted",
        label: "外部订单已受理 · 待商户确认档期",
        ...(parts.filter(Boolean).length > 0 ? { detail: parts.filter(Boolean).join(" · ") } : {}),
        tone: "info",
      };
    }

    default:
      return null;
  }
}

/**
 * 由"能力 + 执行结果 + 裁决终态"推出业务态。
 *
 * 判定顺序(31 文档 §4.2,不可调换):
 *   ① terminal=denied → blocked:被拦下的请求描述的是"没办成",不能被能力标签盖住;
 *   ② terminal=handoff → handoff;
 *   ③ 客户放弃 → cancelled;
 *   ④ 执行失败 → failed;
 *   ⑤ 还没执行(只展示了确认卡)→ pending / 只读 → inquiry;
 *   ⑥ 能力专属口径(含"已提交待审"的那几类);
 *   ⑦ 其余:标了 submitted 的能力 → submitted;只读 → inquiry;否则 done。
 */
export function deriveOperationStatus(input: OperationStatusInput): OperationStatusInfo {
  const { capability, outcome, terminal, pendingTier } = input;
  const data = asRecord(outcome?.data);

  // ① 策略拦截 / 应办但必须转人工
  if (terminal?.kind === "denied") {
    const credentialChange = capability === "security.change_phone" || capability === "security.change_password";
    if (credentialChange) {
      return {
        status: "blocked",
        label: "未代理 · 已引导自助",
        detail: "官方入口:App「我的 → 安全中心」",
        tone: OPERATION_STATUS_TONE.blocked,
      };
    }
    const detail = input.denyReason ?? terminal.detail;
    return {
      status: "blocked",
      label: "已拦截",
      ...(detail ? { detail } : {}),
      tone: OPERATION_STATUS_TONE.blocked,
    };
  }
  if (terminal?.kind === "handoff") {
    return {
      status: "handoff",
      label: "已转人工审批",
      ...(terminal.detail ? { detail: terminal.detail } : {}),
      tone: OPERATION_STATUS_TONE.handoff,
    };
  }

  // ② 客户放弃当前这笔(取消了待确认动作,没有执行任何能力)
  if (input.cancelled) {
    return { status: "cancelled", label: "已取消", tone: OPERATION_STATUS_TONE.cancelled };
  }

  // ③ 执行失败:能力层返回 ok=false,没有任何副作用
  if (outcome && outcome.ok === false) {
    return { status: "failed", label: "办理失败", tone: OPERATION_STATUS_TONE.failed };
  }

  // ④ 还没执行 —— 只展示了确认卡 / 强验证卡。这是"此刻的状态",不是历史操作
  if (!outcome) {
    if (pendingTier) {
      return {
        status: "pending",
        label: pendingTier === "strong_auth" ? "待您验证" : "待您确认",
        tone: OPERATION_STATUS_TONE.pending,
      };
    }
    const readOnly = input.readOnly ?? looksReadOnly(capability);
    if (readOnly) return { status: "inquiry", label: "仅查询", tone: OPERATION_STATUS_TONE.inquiry };
    return { status: "pending", label: "待办理", tone: OPERATION_STATUS_TONE.pending };
  }

  // ⑤ 能力专属口径(真实字段)
  const specific = capabilityStatus(capability, data);
  if (specific) return specific;

  // ⑥ 通用兜底
  if (SUBMITTED_CAPABILITIES.has(capability)) {
    return { status: "submitted", label: "已提交 · 待处理", tone: OPERATION_STATUS_TONE.submitted };
  }
  if (input.readOnly ?? looksReadOnly(capability)) {
    return { status: "inquiry", label: "仅查询", tone: OPERATION_STATUS_TONE.inquiry };
  }
  return { status: "done", label: "已办结", tone: OPERATION_STATUS_TONE.done };
}

/** 会话级状态:按 §4.3 的优先级挑最需要关注的一个 */
export function mostSevereStatus(statuses: OperationStatus[]): OperationStatus {
  if (statuses.length === 0) return "inquiry";
  for (const candidate of OPERATION_STATUS_PRIORITY) {
    if (statuses.includes(candidate)) return candidate;
  }
  return "inquiry";
}
