/**
 * 办理流程可视化(Flow Trace)
 *
 * ★ 核心设计立场:**流程不是画出来的,是从审计链里读出来的。**
 *
 *   很多"流程图"是假的 —— 页面自己写死一条步骤列表,执行到哪一步由前端猜。
 *   那种图迟早会和真实链路不一致,而且不一致的时候没人知道。
 *
 *   这里反过来:同一个 traceId 下**真实发生过的审计事件**,
 *   逐条翻译成人话与视觉步骤。于是:
 *     · 界面上显示"已策略校验" ⇔ 审计里必有 `policy_evaluated`;
 *     · 界面上显示"已转人工审批" ⇔ 审计里必有 `handoff_to_human`;
 *     · 界面上显示"已办结" ⇔ 审计里必有 `execution_completed`。
 *   两者不可能各说各话 —— 因为它们是同一份数据的两种渲染。
 *
 * ★ 第二条立场:**每一步都标注归谁办**(lane)。
 *   Agent 自主执行、必须客户授权、必须客户本人验证、已转人工审批、已被阻断,
 *   五个值是流程节点上的字段而不是一句口头说明 —— 这样"自主 vs 审批"的边界
 *   在界面上是**看得见**的,而不是靠 Agent 自述。
 */

import type { AuditEvent } from "../types.ts";
import {
  formatCitationLine,
  type FlowLane,
  type FlowStep,
  type FlowTrace,
  type ProactiveSuggestion,
  type SavedFlowTemplate,
  type SourceCitation,
  type TemplateParam,
  type TurnExtras,
  type VisualBlock,
} from "./turnExtras.ts";
import { approvalRuleFor, renderHandoffNotice, type ApprovalRule } from "./approval.ts";
import { condenseForCustomer } from "./brevity.ts";
import { capabilityLabel } from "./capabilityLabels.ts";
import { fmtMoney } from "../util/format.ts";

// ============================================================================
// 业务族(用于"常用流程"的识别与命名)
// ============================================================================

export interface FlowFamily {
  /** 稳定族键,如 transfer / wealth_purchase */
  key: string;
  /** 面向客户的名字,如「转账汇款」 */
  label: string;
  /**
   * 是否值得存为常用流程。
   * 只读查询(看余额、看账单)不存 —— 存一堆"查余额"只会把常用服务塞满。
   */
  saveable: boolean;
}

const FAMILIES: Record<string, FlowFamily> = {
  "transfer.submit": { key: "transfer", label: "转账汇款", saveable: true },
  "transfer.create_schedule": { key: "transfer_schedule", label: "定时转账", saveable: true },
  "transfer.cancel_schedule": { key: "transfer_schedule_cancel", label: "取消定时转账", saveable: false },
  "transfer.cancel": { key: "transfer_cancel", label: "转账撤销", saveable: false },
  "collection.create": { key: "collection", label: "AA 收款", saveable: true },
  "collection.remind": { key: "collection_remind", label: "收款催办", saveable: false },
  "wealth.purchase": { key: "wealth_purchase", label: "理财申购", saveable: true },
  "wealth.redeem": { key: "wealth_redeem", label: "理财赎回", saveable: true },
  "wealth.risk_assess": { key: "wealth_assess", label: "风险测评", saveable: false },
  "wealth.rollover_plan": { key: "wealth_rollover_plan", label: "到期续接方案", saveable: false },
  "wealth.rollover_choose": { key: "wealth_rollover_choose", label: "登记续接选择", saveable: false },
  "card.report_loss": { key: "card_loss", label: "挂失冻结", saveable: false },
  "card.replace": { key: "card_replace", label: "补卡申请", saveable: true },
  "card.unblock": { key: "card_unblock", label: "解除限制申请", saveable: false },
  "card.limit_adjust": { key: "card_limit", label: "额度调整申请", saveable: false },
  "card.new_application": { key: "card_new", label: "新卡申请", saveable: true },
  "card.activate": { key: "card_activate", label: "卡片激活", saveable: false },
  // ★ 订阅代扣:取消是一个"会被客户反复问起"的动作,单独给族名;
  //   识别与提醒是问答类,只用于会话标题(不给快捷入口 —— 没人需要
  //   "再识别一次我的订阅"这种按钮,他随时可以再问一句)。
  "subscription.cancel": { key: "subscription_cancel", label: "取消订阅代扣", saveable: false },
  "subscription.scan": { key: "subscription_scan", label: "订阅代扣识别", saveable: false },
  "subscription.list": { key: "subscription_renewal", label: "续费提醒", saveable: false },
  "subscription.detail": { key: "subscription_detail", label: "订阅详情", saveable: false },
  // ★ 跨场景事件联动(场景六)。
  //   方案生成与事件清单是问答类(不给快捷入口 —— 客户随时可以再问一句),
  //   而"资金操作/外部服务操作"值得单独给族名:它们各自是一次会被反复追问的办理
  //   (「我上次订的那束花什么时候到」),会话标题必须能说清是哪一类。
  "cross_scene_event_planning": { key: "event_plan", label: "跨场景联动方案", saveable: false },
  "event.list": { key: "event_list", label: "关键事件清单", saveable: false },
  "event.register": { key: "event_register", label: "登记关键事件", saveable: false },
  "event.fund_step": { key: "event_fund_step", label: "联动·资金操作", saveable: false },
  "event.external_step": { key: "event_external_step", label: "联动·外部服务操作", saveable: false },
  "note.create": { key: "note_create", label: "记账批注", saveable: false },
  // ★ 下面三个是"问答类"能力。它们不会出现在常用流程里(saveable=false),
  //   但会话标题会用到族名 —— 不登记的话,客户在历史列表里看到的是
  //   「memory.search」「document.compare」这种**内部能力名**。
  //   界面上的每个字都应该是人话,这是本项目的一贯要求。
  "policy.search": { key: "policy_search", label: "制度问答", saveable: false },
  "memory.search": { key: "memory_search", label: "历史记录查询", saveable: false },
  "document.compare": { key: "document_compare", label: "材料比对", saveable: false },
  "security.change_phone": { key: "security_phone", label: "修改手机号", saveable: false },
  "security.change_password": { key: "security_password", label: "修改密码", saveable: false },
  // ★ 转人工也是一个"客户会回头找"的节点(他要知道那次到底是转了人工还是没办成),
  //   所以它需要自己的族名。不登记的话它会落到下面的前缀兜底里,而 "human"
  //   不在 labelMap 中 —— 台账的 family 就会被写成内部能力名,历史列表里
  //   整行显示成「human.handoff」(实测数据 var/personalization/ 里就有这一行)。
  "human.handoff": { key: "human_handoff", label: "人工协助", saveable: false },
};

/**
 * 只有这些业务族才值得进常用服务。
 *
 * ★ 为什么用白名单而不是"排除查询类":
 *   实测踩到(而且是最难看的一种):把只读能力也当作可保存,
 *   客户文件里就长出了「账户与账单查询 · account.report」这种条目 ——
 *   名字里带着**内部英文能力名**,而且"再办一次查账单"本来就不需要快捷入口。
 *   常用服务是要被客户天天看见的地方,放进去的每一条都得是他真的想再办一次的事。
 *   所以判据倒过来:**只有明确列出的业务动作才算流程**。
 */
const SAVEABLE_FAMILIES = new Set([
  "transfer",
  "transfer_schedule",
  "collection",
  "wealth_purchase",
  "wealth_redeem",
  "card_replace",
  "card_new",
  "note_create",
]);

/** 取能力所属的业务族(只读能力也返回族,但 saveable=false) */
export function flowFamilyOf(capability: string): FlowFamily {
  const known = FAMILIES[capability];
  if (known) return known;

  const prefix = capability.split(".")[0] ?? capability;
  const labelMap: Record<string, string> = {
    account: "账户与账单查询",
    payee: "收款人查询",
    card: "卡片管理",
    wealth: "理财服务",
    transfer: "转账汇款",
    collection: "AA 收款",
    note: "记账",
    security: "安全设置",
    subscription: "订阅代扣管理",
    event: "跨场景事件联动",
  };
  return {
    key: capability,
    label: labelMap[prefix] ?? capability,
    // 未登记的能力一律不存:宁可少一个快捷入口,也不要一个看不懂的入口
    saveable: SAVEABLE_FAMILIES.has(capability),
  };
}

// ============================================================================
// 步骤映射:审计事件 → 面向客户的流程步骤
// ============================================================================

const LANE_TEXT: Record<FlowLane, string> = {
  auto: "Agent 自主执行",
  customer: "等您确认",
  customer_auth: "需您本人验证",
  human_review: "已转人工审批",
  blocked: "已被拦截",
};

export function laneLabel(lane: FlowLane): string {
  return LANE_TEXT[lane];
}

interface MappedStep extends FlowStep {
  /** 排序用:同一时刻内向后的顺序 */
  order: number;
}

function str(v: unknown, fallback = ""): string {
  return typeof v === "string" && v.length > 0 ? v : fallback;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** 把一条审计事件映射为一个流程步骤;返回 null 表示这条事件不面向客户展示 */
function mapEvent(e: AuditEvent, order: number): MappedStep | null {
  const p = e.payload ?? {};
  const base = { ts: e.ts, auditType: e.type, order };

  switch (e.type) {
    case "envelope_received": {
      return {
        ...base,
        id: `s${order}`,
        label: "收到您的请求",
        detail: "已建立本轮追踪 ID,后续每一步都会写进审计哈希链",
        status: "done",
        lane: "auto",
      };
    }

    case "intent_parsed": {
      const parsed = p["parsed"] as Record<string, unknown> | null | undefined;
      if (p["stage"] === "confirmation_by_anaphoric_reference") {
        return {
          ...base,
          id: `s${order}`,
          label: "理解为「按卡上这个办」",
          detail: "指代对象是屏幕上唯一的那张卡",
          status: "done",
          lane: "auto",
        };
      }
      if (!parsed) {
        // 解析失败的记录不必单独成步(会由"未能理解"那条兜底回复体现)
        return null;
      }
      return {
        ...base,
        id: `s${order}`,
        label: "理解为您的意图",
        detail: str(parsed["restatedIntent"], "已完成意图解析"),
        status: "done",
        lane: "auto",
      };
    }

    case "plan_created": {
      const total = num(p["total"]) ?? 0;
      const stage = str(p["stage"]);
      if (stage === "preview") {
        const steps = (p["steps"] as Array<{ label?: string }> | undefined) ?? [];
        return {
          ...base,
          id: `s${order}`,
          label: `把这件事拆成 ${total} 步`,
          detail: steps.map((s, i) => `${i + 1}. ${str(s.label, "一件事")}`).join("  "),
          status: "active",
          lane: "auto",
        };
      }
      return {
        ...base,
        id: `s${order}`,
        label: `执行计划(${total} 步)${str(p["status"]) ? ` · ${str(p["status"])}` : ""}`,
        detail: str(p["restatedIntent"]),
        status: p["status"] === "completed" ? "done" : "active",
        lane: "auto",
      };
    }

    case "capability_invoked": {
      /**
       * ★ 这一行原来直接写内部能力名(如 `transfer.submit`),而它会渲染在
       *   客户看到的流程链上(public/app.js 把 detail 当正文一行显示)。
       *   实测:客户问「刚才那步是什么」,答复里出现的是 `transfer.submit`。
       *   术语换成人话 —— 能力名到客户说法的映射与别处共用同一张表。
       */
      const capName = str(p["capability"]);
      return {
        ...base,
        id: `s${order}`,
        label: "执行这项操作",
        detail: `${capName ? capabilityLabel(capName) : "操作"}${p["readOnly"] === true ? "(只读,不改动任何东西)" : ""}`,
        status: "done",
        lane: "auto",
      };
    }

    case "policy_evaluated": {
      const effect = str(p["effect"]);
      const reasons = (p["reasons"] as Array<{ ruleId?: string; message?: string }> | undefined) ?? [];
      const shown = reasons.slice(-2).map((r) => `[${str(r.ruleId, "-")}] ${str(r.message)}`);
      const more = reasons.length > 2 ? `(另 ${reasons.length - 2} 条见审计)` : "";
      const lane: FlowLane =
        effect === "handoff" ? "human_review" : effect === "deny" ? "blocked" : "auto";
      const label =
        effect === "deny"
          ? "策略校验:拦截"
          : effect === "handoff"
            ? "策略校验:超出自主办理范围"
            : "策略校验通过(纯确定性规则,模型未参与)";
      return {
        ...base,
        id: `s${order}`,
        label,
        detail: [shown.join(";"), more].filter(Boolean).join(" "),
        status: effect === "deny" ? "failed" : "done",
        lane,
      };
    }

    case "payload_frozen": {
      return {
        ...base,
        id: `s${order}`,
        label: "冻结本次办理内容(哈希绑定)",
        detail: "您确认的内容与将要执行的内容由载荷哈希保证一致",
        status: "done",
        lane: "auto",
      };
    }

    case "confirm_presented": {
      return {
        ...base,
        id: `s${order}`,
        label: "已备好待确认内容,等您确认后才执行",
        /**
         * ★ 这一步**刻意不带金额明细**。
         *
         *   踩过的坑(被测试抓到的真问题):客户说「金额改成200」时,
         *   系统会重述"已把金额从 ¥2,000 改为 ¥200"并附上一张**新卡**;
         *   而这轮流程里会带出"上一轮冻结的 ¥2,000"那一步 ——
         *   于是回复里同时出现 2,000 与 200,客户完全无法判断
         *   屏幕上这张卡到底要转多少。
         *
         *   交互原则:**确认卡上的数字必须是唯一真相**。
         *   流程只回答"你在哪一步、下一步归谁",不复述金额 ——
         *   金额由卡本身(以及本轮的主回复)负责。
         */
        status: "waiting",
        lane: "customer",
      };
    }

    case "strong_auth_requested": {
      const methods = (p["authMethods"] as string[] | undefined) ?? [];
      return {
        ...base,
        id: `s${order}`,
        label: "需要您本人完成身份验证",
        detail:
          methods.map((m) => authMethodText(m)).join(" + ") +
          "(验证由外部安全环境完成,Agent 不接触生物特征)",
        status: "waiting",
        lane: "customer_auth",
      };
    }

    case "strong_auth_completed": {
      const valid = p["valid"] === true;
      return {
        ...base,
        id: `s${order}`,
        label: valid ? "身份验证通过(回执验签成功)" : "身份验证未通过(回执签名无效)",
        detail: `签发方 ${str(p["issuer"], "外部安全环境")}`,
        status: valid ? "done" : "failed",
        lane: valid ? "auto" : "blocked",
      };
    }

    case "execution_started": {
      const cap = str(p["capability"]);
      return {
        ...base,
        id: `s${order}`,
        label: `${flowFamilyOf(cap).label}:开始执行`,
        detail: p["moneyMovement"] === true ? "涉及资金变动" : "非资金操作",
        status: "active",
        lane: "auto",
      };
    }

    case "execution_completed": {
      const cap = str(p["capability"]);
      const disposition = str(p["disposition"]);
      if (disposition.startsWith("user_")) {
        return {
          ...base,
          id: `s${order}`,
          label: "已取消,未执行任何操作",
          detail: "取消记录同样入链",
          status: "done",
          lane: "customer",
        };
      }
      const ok = p["ok"] !== false;
      const money = num((p["resultData"] as Record<string, unknown> | undefined)?.["amount"]);
      return {
        ...base,
        id: `s${order}`,
        label: ok ? `${flowFamilyOf(cap).label}:已办结` : `${flowFamilyOf(cap).label}:执行失败`,
        detail: [str(p["summary"]), money != null ? `金额 ${money} 元` : ""].filter(Boolean).join(" · ") || undefined,
        status: ok ? "done" : "failed",
        lane: ok ? "auto" : "blocked",
      };
    }

    case "execution_failed": {
      const cap = str(p["capability"]);
      const err = p["error"] as Record<string, unknown> | undefined;
      return {
        ...base,
        id: `s${order}`,
        label: `${flowFamilyOf(cap).label}:执行失败`,
        detail: str(err?.["message"], "系统未返回失败原因") ,
        status: "failed",
        lane: "blocked",
      };
    }

    /**
     * ★ 提交点之前的干净中止(第 3 项)。
     *
     * 它必须与"执行失败"分开显示:客户/监管看到"执行失败"会以为钱可能动过,
     * 而这条的含义恰恰相反 —— **余额与状态一个字节都没动**。
     * 流程卡上的措辞也因此不能写成"失败",要写"已中止(未扣款)"。
     */
    case "execution_cancelled": {
      const cap = str(p["capability"]);
      const op = str(p["op"], cap);
      return {
        ...base,
        id: `s${order}`,
        label: `${flowFamilyOf(cap).label}:已取消(未扣款)`,
        // ★ 卡片上只说客户能懂、能行动的事实;上游 reason 留在审计链里
        detail: "没有扣款,余额没有任何变化 · 需要的话可以重新发起",
        // ★ 用既有的 skipped 而不是新造一个状态:语义正是"这一步没有发生"
        //   (failed 会被读成"试着做了、可能改了状态",那是相反的结论)。
        status: "skipped",
        lane: "customer",
        ...(op ? {} : {}),
      };
    }

    /**
     * ★ 提交之后的补救(第 3 项)。
     *
     * 这两条事件原本只在类型联合里存在、从未被写过。现在它们是"钱已经出去、
     * 靠补偿撤回来"的唯一独立证据 —— 只在 plan_finished 的数组里看一眼是不够的,
     * 因为审计要能被**检索**。
     */
    case "compensation_started": {
      const cap = str(p["capability"]);
      return {
        ...base,
        id: `s${order}`,
        label: "该步骤已提交,开始补偿",
        detail: [str(p["nodeId"]), `补偿动作:${flowFamilyOf(cap).label}`].filter(Boolean).join(" · "),
        status: "active",
        lane: "auto",
      };
    }

    case "compensation_completed": {
      const cap = str(p["capability"]);
      const ok = p["ok"] !== false;
      return {
        ...base,
        id: `s${order}`,
        label: ok ? "补偿已完成(资金已退回)" : "补偿未成功,已转人工",
        detail: [str(p["summary"]), `${flowFamilyOf(cap).label}`].filter(Boolean).join(" · "),
        status: ok ? "done" : "failed",
        lane: ok ? "auto" : "blocked",
      };
    }

    case "handoff_to_human": {
      const disposition = str(p["disposition"]);
      if (disposition === "blocked_by_policy") {
        return {
          ...base,
          id: `s${order}`,
          label: "这一步不能由我代办",
          detail: "已引导您走官方安全流程(不是在拒绝您,是在保护您的账户)",
          status: "failed",
          lane: "blocked",
        };
      }
      return {
        ...base,
        id: `s${order}`,
        label: "已转人工审批",
        detail: [
          str(p["urgency"]) === "high" ? "优先级:高" : "",
          str(p["contextSummary"]),
        ]
          .filter(Boolean)
          .join(" · ") || undefined,
        status: "waiting",
        lane: "human_review",
      };
    }

    case "request_rejected": {
      return {
        ...base,
        id: `s${order}`,
        label: "已拒绝该请求",
        detail: str(p["reason"], str(p["note"])),
        status: "failed",
        lane: "blocked",
      };
    }

    case "clarification_requested": {
      return {
        ...base,
        id: `s${order}`,
        label: "需要您补充一点信息(不猜)",
        detail: str(p["kind"]),
        status: "waiting",
        lane: "customer",
      };
    }

    case "injection_detected": {
      return {
        ...base,
        id: `s${order}`,
        label: "检测到越权指令,已记录但未提权",
        detail: "模型在架构上无权改变策略裁决,因此这类指令无法提权",
        status: "done",
        lane: "auto",
      };
    }

    case "hallucination_blocked": {
      const hits = (p["hits"] as string[] | undefined) ?? [];
      return {
        ...base,
        id: `s${order}`,
        label: "输出侧合规闸门:已改写违规表述",
        detail: hits.join(" / "),
        status: "done",
        lane: "auto",
      };
    }

    case "wealth_assessment_completed":
      return {
        ...base,
        id: `s${order}`,
        label: "风险承受能力测评已完成",
        detail: `等级 ${str(p["level"])}(${str(p["levelLabel"])})`,
        status: "done",
        lane: "auto",
      };

    case "wealth_consent_signed":
      return {
        ...base,
        id: `s${order}`,
        label: "《风险不匹配确认书》已签署",
        detail: `编号 ${str(p["consentRef"])} · 绑定「客户+产品+金额」`,
        status: "done",
        lane: "customer",
      };

    case "wealth_risk_disclosure_sent":
      return {
        ...base,
        id: `s${order}`,
        label: "已做风险揭示",
        detail: "理财非存款,产品有风险,投资须谨慎",
        status: "done",
        lane: "auto",
      };

    case "card_loss_reported":
      return {
        ...base,
        id: `s${order}`,
        label: "挂失已受理并冻结",
        detail: `卡 ${str(p["cardLast4"])} · 紧急止损优先于任何待办`,
        status: "done",
        lane: "auto",
      };

    case "card_limit_application_submitted":
      return {
        ...base,
        id: `s${order}`,
        label: "额度调整申请已提交",
        detail: "★ 申请 ≠ 已生效,最终以银行审核结果为准",
        status: "waiting",
        lane: "human_review",
      };

    case "card_unblock_requested":
      return {
        ...base,
        id: `s${order}`,
        label: "解除限制申请已提交",
        detail: "★ 是否解除由银行审核决定,不是我这里说了算",
        status: "waiting",
        lane: "human_review",
      };

    case "card_replacement_ordered":
      return {
        ...base,
        id: `s${order}`,
        label: "补卡申请已提交",
        detail: `方式:${str(p["mode"])} · 预计 ${str(p["etaDays"])} 个工作日`,
        status: "waiting",
        lane: "auto",
      };

    case "card_restriction_inquired":
      return {
        ...base,
        id: `s${order}`,
        label: "已查清限制原因",
        detail: str(p["causeLabel"]),
        status: "done",
        lane: "auto",
      };

    case "card_credential_change_blocked":
      return {
        ...base,
        id: `s${order}`,
        label: "改手机号/改密码:不代理",
        detail: "只能由您在 App 安全中心本人完成 —— 账户接管最常走这条路",
        status: "failed",
        lane: "blocked",
      };

    case "card_activation_completed":
      return {
        ...base,
        id: `s${order}`,
        label: "卡片激活完成",
        detail: p["transactionPasswordSet"] === true ? "已设置交易密码" : "沿用原交易密码",
        status: "done",
        lane: "auto",
      };

    case "subscription_scanned":
      return {
        ...base,
        id: `s${order}`,
        label: "已识别订阅代扣",
        detail: `识别 ${str(p["totalCount"])} 笔 · 每月合计 ¥${str(p["monthlyTotal"])} —— 依据关键词与固定周期金额,金额来自流水`,
        status: "done",
        lane: "auto",
      };

    case "subscription_renewal_reminded":
      return {
        ...base,
        id: `s${order}`,
        label: "已提示即将扣款",
        detail: `未来 ${str(p["withinDays"])} 天 ${str(p["upcomingCount"])} 笔 · 合计 ¥${str(p["upcomingTotal"])}`,
        status: "done",
        lane: "auto",
      };

    case "subscription_cancelled":
      return {
        ...base,
        id: `s${order}`,
        label: "代扣协议已解除",
        detail:
          `${str(p["merchantName"])} · 下一期起不再扣款 · 本期已扣费用按协议处理` +
          `${p["nextDebitAtAfter"] == null ? "" : "(★ 仍有下次扣款日,需核查)"}`,
        status: "done",
        lane: "auto",
      };

    case "subscription_cancel_rejected":
      return {
        ...base,
        id: `s${order}`,
        label: "取消订阅:未执行",
        detail: `${str(p["code"])} —— ${p["executed"] === false ? "没有产生任何取消操作,已如实告知客户原因" : ""}`,
        status: "failed",
        lane: "blocked",
      };

    // ---- 跨场景事件联动(新场景)----
    //
    // ★ 这一族事件在流程图上必须能看出**"方案 ≠ 执行"**这件事:
    //   event_plan_generated 画在 auto 道(只读),而且 detail 里明确写"未执行任何步骤";
    //   event_plan_step_confirmed 才画在 auto 道且写清是哪一步、多少钱、去哪。
    //   两者分开,复盘时才能回答"客户看到方案之后,到底确认了哪一步"。
    case "event_plan_generated":
      return {
        ...base,
        id: `s${order}`,
        label: "已生成跨场景联动方案",
        detail:
          `${str(p["eventTitle"])}(${str(p["daysUntil"])} 天后)· ${str(p["steps"] ? (p["steps"] as unknown[]).length : 0)} 步 · ` +
          `资金操作 ¥${str(p["fundTotal"])} / 外部服务 ¥${str(p["externalTotal"])} —— 未执行任何步骤`,
        status: "done",
        lane: "auto",
      };

    case "event_plan_step_confirmed": {
      const isExternal = p["domain"] === "external";
      return {
        ...base,
        id: `s${order}`,
        label: isExternal ? "已提交外部订单(需强验证)" : "已执行资金操作步骤",
        detail:
          `${str(p["stepId"])} · ${isExternal ? `商户 ${str(p["toName"] ?? p["merchantName"])}` : `去向 ${str(p["toName"])}`} · ` +
          `¥${str(p["amount"])} · 仅此一步,其它步骤未执行`,
        status: "done",
        lane: "auto",
      };
    }

    case "event_external_order_placed":
      return {
        ...base,
        id: `s${order}`,
        label: "外部订单已提交",
        detail:
          `${str(p["merchantName"])} · ${str(p["item"])} · ¥${str(p["amount"])} · ${str(p["status"])} —— ` +
          `钱已离开银行体系,退改需与商户协商`,
        status: "done",
        lane: "auto",
      };

    case "event_plan_step_rejected":
      return {
        ...base,
        id: `s${order}`,
        label: "联动方案步骤:未执行",
        detail: `${str(p["code"])} —— ${p["executed"] === false ? "没有产生任何资金变动或订单,已如实告知客户原因" : ""}`,
        status: "failed",
        lane: "blocked",
      };

    default:
      return null;
  }
}

function authMethodText(m: string): string {
  return (
    {
      biometric: "人脸/指纹识别",
      sms_otp: "短信验证码",
      usb_key: "U 盾",
      password: "交易密码",
      trusted_device: "可信设备确认",
    }[m] ?? m
  );
}

/**
 * 从审计事件里把"上一轮展示给客户的确认卡"还原出来。
 *
 * ★ 为什么可以还原得准:审计里存的是**冻结载荷**(stripPrivateFields 之后的),
 *   而 `buildConfirmCard` 本来就是从同一份载荷渲染出那张卡的 ——
 *   两边读的是同一份数据,所以还原出来的字段与客户当时看到的字段一致。
 *
 * ★ 只处理与"常用流程模板"有关的几类字段(对象、金额、备注):
 *   账号、手机号这类敏感字段在这里**主动丢弃** —— 模板不该携带它们。
 *
 * ★ 返回值带上 `capability`:调用方必须先确认"这张卡属于当前这件事"再使用。
 *   否则会出现「在办新卡,卡上却挂着上一笔转账的收款人和金额」这种错位。
 */
function lastConfirmCard(previous: AuditEvent[]): {
  capability: string;
  title: string;
  fields: Array<{ label: string; value: string }>;
} | undefined {
  for (let i = previous.length - 1; i >= 0; i--) {
    const e = previous[i]!;
    if (e.type !== "confirm_presented" && e.type !== "strong_auth_requested") continue;
    const p = e.payload ?? {};
    const frozen = (p["frozenPayload"] as Record<string, unknown> | undefined) ?? {};
    const subject = (p["authSpecSubject"] as Record<string, unknown> | undefined) ?? undefined;
    const fields = cardFieldsFromPayload(subject ?? frozen);
    if (fields.length === 0) continue;
    return { capability: str(p["capability"]), title: str(p["capability"], "待确认操作"), fields };
  }
  return undefined;
}

/**
 * 供服务端在保存常用流程时复用:从审计事件里取回"客户当时看到的那张确认卡"。
 *
 * ★ 为什么必须复用同一份实现:模板的字段直接决定客户下次看到的名称与参数。
 *   如果服务端自己再写一套"从载荷取字段"的逻辑,两处迟早会不一致 ——
 *   一处把"备注"当固定值、另一处当参数,客户就会看到两条不同的常用流程。
 */
export const lastConfirmCardOf = lastConfirmCard;

/** 冻结载荷 → 客户看得懂的几个字段(与 policy/engine.ts 的确认卡口径一致) */
function cardFieldsFromPayload(frozen: Record<string, unknown>): Array<{ label: string; value: string }> {
  const fields: Array<{ label: string; value: string }> = [];
  const push = (label: string, value: string | null): void => {
    if (value) fields.push({ label, value });
  };

  push("收款人", typeof frozen["payeeName"] === "string" ? frozen["payeeName"] : null);
  push("产品", typeof frozen["productName"] === "string" ? frozen["productName"] : null);
  const cardLast4 = frozen["last4"] ?? frozen["__cardLast4"];
  push("卡片", cardLast4 != null ? `尾号 ${String(cardLast4)}` : null);
  const amount = num(frozen["amount"]);
  if (amount != null) push("金额", `¥${formatAmount(amount)}`);
  const total = num(frozen["totalAmount"]);
  if (total != null) push("金额", `¥${formatAmount(total)}`);
  push("备注", typeof frozen["memo"] === "string" && frozen["memo"] ? frozen["memo"] : null);
  // ★ 刻意不导出:账号、手机号、证件号、确认书编号 —— 模板不该携带敏感字段
  return fields;
}

/** 两位小数金额(口径见 util/format.ts,单一实现) */
const formatAmount = (amount: number): string => fmtMoney(amount);

// ============================================================================
// 事务族合并:把"确认卡发出的那一轮"与"确认后执行的那一轮"接成一条链
// ============================================================================

/**
 * 把上一轮同一族业务里"仍在等待"的步骤补到本轮前面。
 *
 * ★ 为什么需要:资金类操作天然跨两轮 ——
 *   第 1 轮展示确认卡(审计里 `confirm_presented`),第 2 轮用户点确认才执行。
 *   如果只看第 2 轮的审计,客户会看到一条"凭空开始"的流程:
 *   没有"等你确认"那一步,也就看不出**是谁批准了这笔钱**。
 *   而这恰恰是本需求最想让人看见的东西。
 */
function carryOver(previous: AuditEvent[], familyKey: string, now: number): MappedStep[] {
  const out: MappedStep[] = [];
  let order = 0;
  for (const e of previous) {
    if (e.type !== "confirm_presented" && e.type !== "strong_auth_requested" && e.type !== "plan_created") continue;
    const cap = str((e.payload ?? {})["capability"]);
    if (cap && flowFamilyOf(cap).key !== familyKey) continue;
    const mapped = mapEvent(e, order);
    if (!mapped) continue;
    out.push({ ...mapped, id: `prev_${mapped.id}`, detail: [mapped.detail, "上一轮已完成这一步"].filter(Boolean).join(" · ") });
    order++;
  }
  // 只带最近 6 小时内的,避免把几天前的流程混进来
  if (out.length > 0 && now - Math.max(...out.map((s) => s.ts)) > 6 * 3600 * 1000) return [];
  return out;
}

// ============================================================================
// 组装
// ============================================================================

export interface BuildFlowInput {
  /** 本轮的审计事件(按 seq 升序) */
  events: AuditEvent[];
  /** 同一客户在本轮之前、同一族业务最近一轮的审计事件(用于把"等你确认"接上) */
  previousEvents?: AuditEvent[];
  extras: TurnExtras;
  reply: string;
  promptKind: string;
  /** 当前时间(注入以便测试可复现) */
  now?: number;
}

export function buildFlowTrace(input: BuildFlowInput): FlowTrace | null {
  const { events, extras } = input;
  const nowTs = input.now ?? Date.now();

  const steps: MappedStep[] = [];
  let order = 0;
  for (const e of pickFlowEvents(events)) {
    const mapped = mapEvent(e, order);
    if (!mapped) continue;
    steps.push(mapped);
    order++;
  }
  if (steps.length === 0) return null;

  /**
   * ★ 补一次"能力"信息:只做了澄清、还没进入裁决的那一轮,
   *   审计里没有 capability 字段(因为还没走到那一步),
   *   但那句话**已经被理解成某个意图**了(审计的 intent_parsed 里有 action)。
   *   用它当流程标题,客户才能看到"系统把我这句话理解成了什么" ——
   *   这正是澄清场景下他最需要知道的信息。
   */
  if (extras.capabilities.length === 0) {
    for (const e of events) {
      if (e.type !== "intent_parsed") continue;
      const parsed = e.payload?.["parsed"] as Record<string, unknown> | undefined;
      const action = typeof parsed?.["action"] === "string" ? parsed["action"] : null;
      if (action) extras.flowKey = flowFamilyOf(action).key;
      if (action && !extras.capabilities.includes(action)) extras.capabilities.push(action);
    }
  }

  /**
   * ★ 还有一种更隐蔽的"没有意图"的轮次:用户只是在确认/验证(或回了一句
   *   「确认」),而这一轮被拒了 —— 没有 intent_parsed(确认动作不重新解析),
   *   也没有执行事件,但裁决/拒绝事件里**带着能力名**。
   *
   *   不补这一步会怎样(实测):客户刚转完一笔给王秀兰,接着办新卡,
   *   办卡这一轮的流程卡就退化成「unknown」;更糟的是它还会顺手借来
   *   上一笔转账的确认卡,于是标题变成「unknown · 王秀兰 ¥500.00」——
   *   明明在办新卡,卡上却挂着一笔 500 元的转账。
   */
  if (extras.capabilities.length === 0) {
    for (const e of events) {
      const cap = str(e.payload?.["capability"]);
      // 只认"命名空间.动作"形状的能力名,避免把业务文案里的 capability 字段当成能力
      if (cap && /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(cap)) {
        extras.capabilities.push(cap);
        extras.flowKey = flowFamilyOf(cap).key;
        break;
      }
    }
  }

  // 跨轮接续:本轮若只含"执行"而不含"等待确认",把上一轮的确认步骤补上
  const hasWaiting = steps.some((s) => s.status === "waiting" && s.lane === "customer");
  const hasCustomerStep = steps.some((s) => s.lane === "customer" || s.lane === "customer_auth");
  let all = steps;
  if (!hasWaiting && !hasCustomerStep && extras.executed && input.previousEvents?.length) {
    const fam = flowFamilyOf(extras.executedCapability ?? extras.capabilities[0] ?? "unknown");
    const carried = carryOver(input.previousEvents, fam.key, nowTs);
    if (carried.length > 0) {
      /**
       * ★ 补回来的那一步"等你确认",在**已办结**的这一轮必须变成"已完成"。
       *
       *   这是客户实测报上来的那个问题:按了确认、钱也转出去了,
       *   流程卡上却还留着一条"… 已备好待确认内容,等你确认后才执行"。
       *   原因是 carryOver 只是把上一轮那一步原样搬过来,搬的是它**当时**的状态。
       *   事实是:既然这一轮已经执行了,这一步就已经被客户批准过了 ——
       *   状态要跟着事实走,而不是跟着事件快照走。
       */
      const settled = carried.map((s) => {
        if (s.status !== "waiting") return s;
        return s.lane === "customer_auth"
          ? { ...s, status: "done" as const, label: "您已完成身份验证" }
          : { ...s, status: "done" as const, label: "您已确认这笔操作" };
      });
      all = [...settled, ...steps];
    }
  }

  // 去掉"开始执行"与"已办结"成对出现时的冗余(后者已含全部信息)
  const trimmed = all.filter((s) => !(s.auditType === "execution_started" && all.some((x) => x.auditType === "execution_completed" && x.ts >= s.ts)));

  const family = flowFamilyOf(extras.executedCapability ?? extras.capabilities[0] ?? "unknown");
  const handedToHuman = trimmed.some((s) => s.lane === "human_review") || extras.handedToHuman;
  const awaitingCustomer =
    input.promptKind === "confirm" ||
    input.promptKind === "strong_auth" ||
    input.promptKind === "clarify" ||
    trimmed.some((s) => s.status === "waiting" && (s.lane === "customer" || s.lane === "customer_auth"));
  const anyFailure = trimmed.some((s) => s.status === "failed");
  const customerAuthorized = trimmed.some(
    (s) => (s.lane === "customer" || s.lane === "customer_auth") && s.status === "done",
  );

  const summary = handedToHuman
    ? "其中有人工审批环节:已转人工,请在下方按清单提交材料"
    : anyFailure
      ? "本次未全部办结,流程明细见下"
      : awaitingCustomer
        ? trimmed.some((s) => s.lane === "customer_auth")
          ? "等您本人完成身份验证后再继续"
          : "已备好待确认内容,您确认后我才执行"
        : extras.executed && customerAuthorized
          ? "已由您确认后办结"
          : "已由 Agent 自主办结(全部为可自主执行的动作)";

  /**
   * ★ 展示字段的来源:优先本轮展示的确认卡;本轮只做"执行"时(跨轮操作),
   *   从上一轮的审计事件里**取回那张卡**。
   *
   * 不取回会怎样(实测踩到):模板退化成「给 {收款人} 转 {金额} 元」这样的空壳 ——
   * 没有对象、没有金额,客户下次看到这条"常用流程"根本认不出它是哪一件事。
   * 常用流程的价值全在"这一套是我常用的那个",空壳模板等于没记住。
   *
   * ★ 但借用必须**同族**:上一轮的卡是"转账"的,这一轮在办"新卡申请",
   *   借过来就是把一件完全无关的事挂到这笔业务上。跨族一律不借 ——
   *   宁可标题少一个对象,也不能让客户以为"办卡"跟那笔 500 元有关。
   */
  const carriedCard = extras.confirmCard ? undefined : lastConfirmCard(input.previousEvents ?? []);
  const shownCard =
    extras.confirmCard ??
    (carriedCard && carriedCard.capability && flowFamilyOf(carriedCard.capability).key === family.key
      ? carriedCard
      : undefined);

  // 标题:族名 + 关键对象
  const highlights = shownCard?.fields
    .filter((f) => ["收款人", "金额", "产品", "卡片", "金额(元)"].some((k) => f.label.includes(k)))
    .slice(0, 2)
    .map((f) => f.value);
  const title = `${family.label}${highlights && highlights.length > 0 ? ` · ${highlights.join(" ")}` : ""}`;

  // ★ 只有**真的执行过**才允许存成常用流程(见 TurnExtras.executed 的说明)
  const saveable =
    family.saveable && extras.executed && !handedToHuman && !anyFailure && Boolean(extras.executedCapability);
  const template =
    saveable && extras.executedCapability
      ? deriveTemplate({
          capability: extras.executedCapability,
          card: shownCard,
          flowLabel: family.label,
          now: nowTs,
        })
      : undefined;

  return {
    threadId: extras.flowThreadId ?? extras.traceId,
    title,
    flowKey: family.key,
    steps: trimmed.map(({ order: _order, ...rest }) => rest),
    summary,
    awaitingCustomer,
    handedToHuman,
    saveable: Boolean(template),
    ...(template ? { template } : {}),
  };
}

// ============================================================================
// 常用流程模板派生
// ============================================================================

/** 敏感字段:绝不进模板(与能力定义里的 sensitiveFields 是同一立场) */
const SENSITIVE_LABEL = /账号|卡号|证件|身份证|手机号|密码|CVV|有效期|回执|哈希|reference|流水/;

/**
 * 把一次成功的办理派生为**可复用的意图模板**。
 *
 * ★ 与"存一条历史流水"的区别:模板里金额是参数、收款人是固定值,
 *   所以下次点一下、填个金额就能再办一遍 —— 这才叫"下次直接调用"。
 */
export function deriveTemplate(input: {
  capability: string;
  card?: { title: string; fields: Array<{ label: string; value: string }> } | undefined;
  flowLabel: string;
  now: number;
  /**
   * 业务对象的别名(如收款人的「老妈」「房东」)。
   *
   * ★ 为什么必须带上:客户平时怎么叫这个人,下次就会怎么说。
   *   模板名叫「转账汇款 · 王秀兰」而客户说「用一下给老妈转账」,
   *   两边对不上,常用流程就变成了"存了但认不出来"。
   *   把别名并入名字与固定字段,匹配时两边都能命中。
   */
  aliases?: string[];
  /** 上一次使用信息(保存时沿用) */
  reuse?: { templateId?: string; useCount?: number; lastUsedAt?: number };
}): SavedFlowTemplate {
  const { capability, card, flowLabel } = input;
  const fields = card?.fields ?? [];

  const params: TemplateParam[] = [];
  const fixed: Record<string, string> = {};

  for (const f of fields) {
    if (SENSITIVE_LABEL.test(f.label)) continue;
    const isAmount = /金额/.test(f.label);
    const isMemo = /备注/.test(f.label);
    if (isAmount) {
      params.push({ key: "amount", label: "金额", required: true, lastValue: stripNumber(f.value), example: stripNumber(f.value) || "500" });
    } else if (isMemo) {
      params.push({ key: "memo", label: "备注", required: false, lastValue: f.value, example: f.value });
    } else {
      fixed[f.label] = f.value;
    }
  }

  const aliases = (input.aliases ?? []).filter((a) => a && a.length >= 2);
  if (aliases.length > 0) fixed["别名"] = aliases.join("/");

  // 没有金额字段的流程(如补卡):仍然是"固定套路",不设必填参数
  const subject = fields.find((f) => /收款人|产品|卡片/.test(f.label));
  const aliasText = aliases.length > 0 ? `(${aliases.join("/")})` : "";
  const name = subject ? `${flowLabel} · ${subject.value}${aliasText}` : flowLabel;

  const sentence = buildSentence(capability, fixed, params);

  return {
    templateId: input.reuse?.templateId ?? templateIdFor(capability, fixed, params),
    name,
    capability,
    sentence,
    params,
    fixed,
    createdAt: input.now,
    ...(input.reuse?.lastUsedAt != null ? { lastUsedAt: input.reuse.lastUsedAt } : {}),
    useCount: input.reuse?.useCount ?? 0,
  };
}

/**
 * 生成常用服务里的"可以直接发出去"的那句话。
 *
 * ★ 与 `instantiateTemplate` 的区别:
 *   后者把参数**填满**(用于真正发起或用例展示),
 *   这里保留 `{参数}` 占位符 —— 因为常用流程的意义是"一套我常用的做法",
 *   金额每次都可能不同。界面上显示「给 王秀兰 转 {金额,如500} 元,备注 {备注,如买菜}」,
 *   客户一眼就知道哪一项要改;点一下则把它放进输入框,改一个数字即可发送。
 */
export function templateToSay(t: SavedFlowTemplate): string {
  return t.sentence.trim();
}

function stripNumber(v: string): string {
  const m = String(v).replace(/[,¥\s]/g, "").match(/-?\d+(\.\d+)?/);
  return m ? m[0] : "";
}

/**
 * 生成自然语言模板。
 *
 * ★ 模板的用途是"下次直接调用":它必须**能过意图解析**,
 *   所以要用客户本来就会说的说法(「给老妈转 500 元,备注 买菜」),
 *   而不是生成一句只有系统看得懂的参数串。
 */
function buildSentence(capability: string, fixed: Record<string, string>, params: TemplateParam[]): string {
  const get = (re: RegExp): string => {
    const hit = Object.entries(fixed).find(([k]) => re.test(k));
    return hit ? hit[1] : "";
  };
  const amount = params.find((p) => p.key === "amount");
  const memo = params.find((p) => p.key === "memo");
  /**
   * ★ 占位符里带上"上次用过的值":`{金额,如500.00}`。
   *
   *   这样模板**本身**就是一句可以立刻执行的话(把占位符填上上次的值即可),
   *   而界面上又能一眼看出哪一项是每次要改的。
   *   如果写成纯占位符 `{金额}`,那这句话在没填参数时是**不能被解析**的 ——
   *   客户点了快捷入口却发出去一句"给 王秀兰 转 元",体验直接崩掉。
   */
  const slot = (p: TemplateParam | undefined, fallback: string): string =>
    p ? `{${p.label},如${p.lastValue || p.example || fallback}}` : `{${fallback}}`;

  const amountText = amount ? slot(amount, "500") : "";
  const memoText = memo ? `,备注 ${slot(memo, "买菜")}` : "";

  if (capability === "transfer.submit" || capability === "transfer.create_schedule") {
    const payee = get(/收款人/);
    const schedule = get(/周期|频率|时间/);
    return `给 ${payee || "{收款人,如王秀兰}"} 转 ${amountText || "{金额,如500}"} 元${memoText}${schedule ? `(${schedule})` : ""}`;
  }
  if (capability === "wealth.purchase" || capability === "wealth.redeem") {
    const product = get(/产品/);
    const verb = capability === "wealth.purchase" ? "买" : "赎回";
    return `${verb} ${amountText || "{金额,如10000}"} 元的${product || "{产品名}"}`;
  }
  if (capability === "collection.create") {
    const matter = get(/事由|说明|标题/);
    return `AA 收 ${amountText || "{金额,如600}"} 元(${matter || "{事由}"})`;
  }
  if (capability === "card.replace") {
    const card = get(/卡片/);
    const mode = get(/方式/);
    return `${card || "那张卡"} 补办${mode ? `(${mode})` : ""}`;
  }
  if (capability === "card.new_application") {
    const kind = get(/卡种|类型|产品/);
    return `办一张新卡${kind ? `(${kind})` : ""}`;
  }
  // 兜底:用固定字段拼一句"再办一次"
  const parts = Object.entries(fixed).map(([k, v]) => `${k} ${v}`);
  return [`再办一次:${capability}`, ...parts, amountText, memoText.replace(/^,/, "")].filter(Boolean).join(" ");
}

/** 稳定模板 ID:同样的套路(同能力 + 同固定字段 + 同参数键)必须得到同一个 ID */
export function templateIdFor(
  capability: string,
  fixed: Record<string, string>,
  params: TemplateParam[],
): string {
  const basis = [
    capability,
    ...Object.entries(fixed).map(([k, v]) => `${k}=${v}`).sort(),
    ...params.map((p) => p.key).sort(),
  ].join("|");
  let h = 0;
  for (let i = 0; i < basis.length; i++) h = (h * 31 + basis.charCodeAt(i)) >>> 0;
  return `flow_${h.toString(16).padStart(8, "0")}`;
}

/**
 * 模板 → 一句可以直接发出去的话。
 *
 * ★ 默认行为是"把占位符填上模板里带的上次值":
 *   这使得常用流程**永远是一句能被解析的完整请求** ——
 *   客户点了快捷入口就能直接发送,不会发出一句带花括号的怪话。
 *   (这一点很重要:模板句若带着未替换的占位符发给意图解析器,
 *    结果是一句谁也看不懂的话,而客户会以为"我明明点了那个按钮"。)
 */
export function instantiateTemplate(t: SavedFlowTemplate, values: Record<string, string> = {}): string {
  const sentence = t.sentence.replace(/\{([^},]+)(?:,如([^}]*))?\}/g, (_m, label: string, example: string) => {
    const param = t.params.find((p) => p.label === label);
    const raw = param ? (values[param.key] ?? param.lastValue ?? param.example ?? example ?? "") : (example ?? "");
    return String(raw).trim();
  });
  return sentence.replace(/\s+/g, " ").trim();
}

/**
 * 判断用户这句话是不是在调用某个常用流程。
 *
 * ★ 为什么需要它:常用流程的模板句里带 `{金额}` 这类占位符,
 *   而用户只会说「用一下给老妈转账」或直接照着说一半。
 *   模板名(如「给老妈转账」)是客户看得见的东西,必须有处可解 ——
 *   与「第 2 张卡」「第 1 个产品」是同一类"给出编号就必须接住"的问题。
 */
/**
 * 模板名 → 特征词(供"点名调用常用流程"的匹配使用)。
 *
 * ★ 这里踩过两个真实的坑,都是"看起来能跑但会认错人"的级别:
 *   ① **括号里的别名被连成一坨**:模板名是「转账汇款 · 王秀兰(老妈/妈/妈妈)」,
 *      如果先把整句压平再去掉标点,会得到 "转账汇款王秀兰老妈" 这样一个词 ——
 *      客户说「用一下给老妈转账」时反而匹配不上(一整坨里不可能包含短句)。
 *      正确做法是**先按分隔符切开、再逐段规整**。
 *   ② **只用一个通用词就命中**:「转账」出现在每条转账流程的名字里,
 *      若判据是"命中任意一个词",客户说「给房东转5800」也会被认成"给王秀兰转账" ——
 *      把收款人换成另一个人,这在银行场景里比"不认"危险得多。
 *      因此通用动词不参与匹配,且命中比例必须过半。
 */
const FLOW_MATCH_GENERIC = /^(转账|汇款|理财|申购|赎回|补卡|办卡|收款|查询|办理|一下|我的|那个|这个|转账汇款)$/;

/** 分隔符:中圆点、顿号、括号、斜杠、空白 —— 别名就是被它们隔开的 */
const FLOW_NAME_SEPARATOR = /[·、,，。:：;；\s/()（）]+/;

function flowNameTokens(name: string): string[] {
  return name
    .split(FLOW_NAME_SEPARATOR)
    .map((w) => w.replace(/\{[^}]*\}/g, "").replace(/[\d.¥￥%]/g, "").trim())
    .filter((w) => w.length >= 2 && !FLOW_MATCH_GENERIC.test(w));
}

function normalizeUtterance(s: string): string {
  return s.replace(/[\s,，。、:：;；"'「」【】()（）·]/g, "").toLowerCase();
}

export function matchSavedFlow(
  text: string,
  flows: Array<{ templateId: string; name: string; capability: string; sentence?: string }>,
): { templateId: string; capability: string; name: string } | null {
  const t = normalizeUtterance(text);
  if (!t) return null;

  let best: { templateId: string; capability: string; name: string; hits: number; score: number } | null = null;

  for (const f of flows) {
    const tokens = flowNameTokens(f.name);
    if (tokens.length === 0) continue;
    const hits = tokens.filter((w) => t.includes(w)).length;
    if (hits === 0) continue;
    const score = hits / tokens.length;
    // 命中的特征词越多越优先;同样多时按命中比例高的优先
    const better = !best || hits > best.hits || (hits === best.hits && score > best.score);
    if (better) best = { templateId: f.templateId, capability: f.capability, name: f.name, hits, score };
  }
  return best ? { templateId: best.templateId, capability: best.capability, name: best.name } : null;
}

// ============================================================================
// 渲染:文本渠道也要看得见流程与出处
// ============================================================================

/** 流程步骤 → 纯文本(用于 IM / 语音等不支持富卡片的渠道,以及审计留痕) */
export function renderFlowLines(flow: FlowTrace, mode: "full" | "compact" = "full"): string[] {
  const lines: string[] = [];
  lines.push(`【办理流程 · ${flow.title}】`);
  flow.steps.forEach((s, i) => {
    const state = s.status === "done" ? "已完成" : s.status === "waiting" ? "待处理" : s.status === "failed" ? "未完成" : "进行中";
    lines.push(`  ${i + 1}. [${state}] ${s.label}(${laneLabel(s.lane)})`);
    if (mode === "full" && s.detail) lines.push(`      ${s.detail}`);
  });
  lines.push(`  → ${flow.summary}`);
  return lines;
}

/** 来源标注 → 纯文本 */
export function renderCitationLines(citations: SourceCitation[]): string[] {
  if (citations.length === 0) return [];
  const lines = ["【数字与规则的出处】"];
  for (const c of citations) {
    lines.push(`  · ${formatCitationLine(c)}`);
    if (c.calculation && c.calculation.length > 0) {
      lines.push(`    计算:${c.calculation.join("  →  ")}`);
    }
    if (c.note) lines.push(`    ${c.note}`);
  }
  return lines;
}

/** 主动建议 → 纯文本(渠道不支持按钮时用编号,与消歧候选同一套约定) */
export function renderSuggestionLines(suggestions: ProactiveSuggestion[]): string[] {
  if (suggestions.length === 0) return [];
  const lines = ["", "接下来如果您愿意,我还可以:"];
  suggestions.slice(0, 3).forEach((s, i) => {
    lines.push(`  ${i + 1}. ${s.text}(回复「${s.say}」即可)`);
  });
  return lines;
}

// ============================================================================
// 出口装饰
// ============================================================================

export interface DecorateResult {
  reply: string;
  flow: FlowTrace | null;
  citations: SourceCitation[];
  suggestions: ProactiveSuggestion[];
}

/**
 * 把流程、出处、建议拼进回复。
 *
 * ★ 顺序是有讲究的:
 *   ① 先给结论(原有回复文本),
 *   ② 再给"这一步办到哪了"(流程),
 *   ③ 再给"这些数字凭什么可信"(出处),
 *   ④ 最后给"还能做什么"(建议)。
 *   把流程放最前面会让人先看过程后看结果;把出处放在流程前会打断阅读。
 *
 * ★ 富渠道(App/Web)**只留结论**:流程卡、出处折叠块、建议气泡已经在那儿了,
 *   再在文本里写一遍等于同一件事说两遍。实测这就是"回复太长"的主要来源 ——
 *   一轮转账确认的文本里有 5 行流程、6 行出处、3 行建议、10 行卡片复述,
 *   真正有用的只有 2 行。
 *   文字渠道(IM/语音)没有这些控件,必须由文本承载,所以仍走完整拼接。
 */
export function decorateTurn(input: {
  reply: string;
  flow: FlowTrace | null;
  citations: SourceCitation[];
  suggestions: ProactiveSuggestion[];
  promptKind: string;
  /** 富卡片 + 交互按钮的渠道(App/Web):文本只留结论 */
  richUi?: boolean;
}): DecorateResult {
  const citations = input.citations.slice(0, 6);
  const suggestions = input.suggestions.slice(0, 3);

  if (input.richUi) {
    return { reply: input.reply.trim(), flow: input.flow, citations, suggestions };
  }

  const sections: string[] = [input.reply.trimEnd()];

  if (input.flow) {
    /**
     * ★ 流程在"办理中"与"已办结"两种状态下都要看得见 —— 这正是需求要的
     *   "展示当前任务的步骤链路"。区别只在详略:
     *     · 有客户动作待办(确认/验证/澄清)时用紧凑模式:
     *       此时屏幕上已经有一张要核对的卡,流程只用来回答"我在哪一步、下一步归谁";
     *     · 办结/转人工/可保存时用完整模式:把每一步的证据一并给出。
     *   实测:等待确认时也打印完整明细,回复会长到需要滚动好几屏 ——
     *   客户核对金额时被细节淹没,流程反而失去了"看清链路"的作用。
     */
    const compact = input.promptKind === "confirm" || input.promptKind === "strong_auth" || input.promptKind === "clarify";
    sections.push(renderFlowLines(input.flow, compact ? "compact" : "full").join("\n"));
  }

  if (citations.length > 0) {
    const lines = renderCitationLines(citations);
    if (lines.length > 0) sections.push(lines.join("\n"));
  }

  const suggestionLines = renderSuggestionLines(input.suggestions);
  if (suggestionLines.length > 0) sections.push(suggestionLines.join("\n").replace(/^\n/, ""));

  return {
    reply: sections.join("\n\n"),
    flow: input.flow,
    citations,
    suggestions,
  };
}

// ============================================================================
// 建议的"规则 → 文案"渲染(供 server 侧的建议端口复用)
// ============================================================================

/**
 * 从审计事件里挑出"值得画进流程"的那些。
 *
 * ★ 为什么要有这一步(而不是把所有事件都画上):
 *   一轮真实对话会产生十几条审计事件(信封、解析、注入检测、裁决、冻结、
 *   执行、发送……)。全画出来是运维日志,不是客户看得懂的流程。
 *   这里按"客户能理解的动作"取**最后一条**(同一轮里有多个能力时,
 *   后一条才代表最终结果),同时剔除纯技术事件。
 */
export function pickFlowEvents(events: AuditEvent[]): AuditEvent[] {
  const PICK = new Set([
    "envelope_received",
    "intent_parsed",
    "plan_created",
    "policy_evaluated",
    "payload_frozen",
    "confirm_presented",
    "strong_auth_requested",
    "strong_auth_completed",
    "execution_completed",
    "execution_failed",
    "handoff_to_human",
    "request_rejected",
    "clarification_requested",
    "injection_detected",
    "hallucination_blocked",
    "wealth_assessment_completed",
    "wealth_consent_signed",
    "wealth_risk_disclosure_sent",
    "card_loss_reported",
    "card_limit_application_submitted",
    "card_unblock_requested",
    "card_replacement_ordered",
    "card_restriction_inquired",
    "card_credential_change_blocked",
    "card_activation_completed",
    // ★ 订阅代扣:这四类都要能画进流程:
    //   识别与提醒是"系统主动做了什么",取消与拒绝是"结果是什么"。
    //   尤其 subscription_cancel_rejected —— 客户日后说"我早就让你们关了"时,
    //   台账里必须能看到当时那一刻系统给出了什么结论。
    "subscription_scanned",
    "subscription_renewal_reminded",
    "subscription_cancelled",
    "subscription_cancel_rejected",
    // ★ 跨场景事件联动:四类都要能画进流程 ——
    //   "方案生成了什么"与"哪一步被确认执行"是两条独立的证据,
    //   少了前者就看不出客户确认的是不是他看过的那一步;少了后者就不知道到底办没办。
    "event_plan_generated",
    "event_plan_step_confirmed",
    "event_external_order_placed",
    "event_plan_step_rejected",
    // ★ 提交点前后的两种结局(第 3 项)必须都能画进流程:
    //   execution_cancelled 证明"停在了提交点之前,没动钱";
    //   compensation_* 证明"已经提交了,靠补偿把钱撤回来"。
    //   少了前者,客户会以为取消等于失败;少了后者,回退这件事在流程上不可见。
    "execution_cancelled",
    "compensation_started",
    "compensation_completed",
  ]);
  /**
   * ★ DEDUP 刻意**不含** execution_cancelled / compensation_*:
   *   多步计划里可能有多个节点各自被取消或各自补偿,只留最后一条会把前几步抹掉 ——
   *   而"哪几步真的动过钱、哪几步没有"恰恰是这里最不能丢的信息。
   */
  const DEDUP = new Set(["execution_completed", "execution_failed", "policy_evaluated", "plan_created"]);

  const picked = events.filter((e) => PICK.has(e.type));
  const lastIndexOf = new Map<string, number>();
  picked.forEach((e, i) => {
    if (DEDUP.has(e.type)) lastIndexOf.set(e.type, i);
  });
  return picked.filter((e, i) => {
    const last = lastIndexOf.get(e.type);
    return last == null || last === i;
  });
}

// ============================================================================
// 回合装饰:编排器出口调用
// ============================================================================

export interface TurnDecorationInput {
  /** 面向用户的主回复(已过输出侧合规闸门) */
  reply: string;
  promptKind: string;
  terminal?: { kind: "denied" | "handoff" | "completed"; detail?: string } | undefined;
  extras: TurnExtras;
  /** 本轮审计事件(由编排器注入,便于 core 不依赖 AuditPort 的实现细节) */
  events: AuditEvent[];
  previousEvents: AuditEvent[];
  /** 主动建议(由宿主机注入的事实快照产生;没有端口就是空数组) */
  suggestions: ProactiveSuggestion[];
  now: number;
}

export interface TurnDecoration {
  /** 最终文本 */
  reply: string;
  flow: FlowTrace | null;
  citations: SourceCitation[];
  suggestions: ProactiveSuggestion[];
  /** 被精简层删掉的句子(进审计,保证"给客户看的是精简版"可复核) */
  removedLines: string[];
  /** 需要单独摆出来的可视块 */
  visual: VisualBlock | null;
}

/**
 * 组装本轮的流程 / 出处 / 建议。
 *
 * ★ 顺序固定为:结论 → 流程 → 出处 → 建议。理由见 `decorateTurn` 的注释。
 * ★ 人工审批的处置说明在这里**强制插入**,而不是靠各条链路自己记得写:
 *   只要这一轮真的转了人工(审计里有 handoff_to_human),客户就一定看得到
 *   "已转人工审批 + 要交什么材料"。承诺要由机制保证,不能靠自觉。
 * ★ 富渠道先做一次**精简**:去掉写给开发/评委的元说明,
 *   再把结论交出去(流程/出处/建议走结构化控件,不进文本)。
 */
export function buildTurnDecoration(input: TurnDecorationInput): TurnDecoration {
  const flow = buildFlowTrace({
    events: input.events,
    previousEvents: input.previousEvents,
    extras: input.extras,
    reply: input.reply,
    promptKind: input.promptKind,
    now: input.now,
  });

  const citations = [...input.extras.citations];
  const richUi = input.extras.richUi;

  // ★ 精简只用于富渠道:文字渠道的"元说明"往往同时承担解释职责,删了会更难懂
  const condensed = richUi ? condenseForCustomer(input.reply) : { text: input.reply, removed: [] };

  const decorated = decorateTurn({
    reply: condensed.text,
    flow,
    citations,
    suggestions: input.suggestions,
    promptKind: input.promptKind,
    richUi,
  });

  /**
   * ★ 人工审批的处置说明在这里**强制插入**,而不是靠各条链路自己记得写:
   *   只要这一轮真的转了人工(以审计事实为准,不以某条链路自称),
   *   客户就一定看得到「已转人工审批 + 要交什么材料 + 从哪交 + 多久出结果」。
   *   承诺要由机制保证,不能靠自觉 —— 只有一句"已转人工"而没说交什么,
   *   客户会在原地等一个不会来的电话。
   */
  const rule = resolveApprovalRule(input.extras, input.terminal, flow?.handedToHuman === true);
  if (rule) {
    const notice = renderHandoffNotice(rule);
    const blocks = decorated.reply.split("\n\n");
    blocks.splice(1, 0, notice);
    decorated.reply = blocks.join("\n\n");
    citations.push({
      id: `human_review:${rule.capability}`,
      topic: `人工审批:${rule.lane}`,
      source: "银行业务规则库 · 人工审批事项清单",
      subject: "本笔申请",
      effective: rule.sla,
      asOf: input.now,
      kind: "rule",
      calculation: rule.materials.map((m, i) => `${i + 1}. ${m}`),
      note: `受理通道:${rule.channel}`,
    });
  }

  return {
    reply: decorated.reply,
    flow: decorated.flow,
    citations,
    suggestions: decorated.suggestions,
    removedLines: condensed.removed,
    visual: input.extras.visual ?? null,
  };
}

/** 本轮是否真的转了人工 —— 以审计事实为准,而不是以某条链路自称 */
function resolveApprovalRule(
  extras: TurnExtras,
  terminal: { kind: "denied" | "handoff" | "completed"; detail?: string } | undefined,
  flowHandedToHuman: boolean,
): ApprovalRule | null {
  /**
   * ★ 判据必须包含"流程里出现了人工审批节点"这一条。
   *
   *   实测踩到:提额申请的业务链路并不会把 terminal 标成 handoff(它是**申请已提交**,
   *   不是转人工客服),`extras.handedToHuman` 也没被置位 —— 但审计里明明有
   *   `card_limit_application_submitted`,流程里也确实画出了「已转人工审批」这一节点。
   *   只看前两个标志,结果就是:界面上显示"已转人工审批",却**没有告诉他交什么材料**。
   *   这正是需求点名要避免的那半句话。
   */
  const handed =
    extras.handedToHuman || terminal?.kind === "handoff" || extras.handoffMaterials.length > 0 || flowHandedToHuman;
  if (!handed) return null;
  const cap = extras.executedCapability ?? extras.capabilities[extras.capabilities.length - 1] ?? "";
  return approvalRuleFor(cap);
}
