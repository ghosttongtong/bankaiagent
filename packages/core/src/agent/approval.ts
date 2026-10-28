/**
 * 人工审批通道(Handoff / Manual Review)
 *
 * 需求原话:"明确区分 Agent 自主执行和人工审批:不重要的流程 Agent 自己做完,
 * 敏感流程明确提示『已转人工审批,请提交材料』。"
 *
 * ★ 这条需求有两个容易做歪的地方,这里刻意都避开了:
 *
 *   **一、不能把"我要你确认"说成"人工审批"。**
 *   资金类操作要求客户点确认,那是**客户授权**,不是人工审批 ——
 *   把两者混为一谈,客户就会以为"银行有人在帮我看这笔钱",从而放松警惕。
 *   所以本文件里的每条规则都写明它属于哪一类:
 *     · agent_autonomous —— Agent 自己做完(只读查询、分析、已授权的低风险写)
 *     · human_review     —— 银行人工审批(额度、限制解除、争议、超限)
 *     · not_delegable    —— 谁都不能代客户做(改手机号、改密码)
 *
 *   **二、不能说"已转人工"却不说"要交什么"。**
 *   只说"已转人工审批"的后果是客户在原地等一个不会来的电话。
 *   真实银行流程里,人工审批的事项都有**明确的材料清单**,这里逐项列出来,
 *   客户才知道下一步该干什么 —— 而且这份清单是随流程一起进审计的规则,不是文案。
 */

export interface ApprovalRule {
  /** 能力名 */
  capability: string;
  /** 事项名(面向客户) */
  lane: string;
  /** 材料清单:客户需要提交什么 */
  materials: string[];
  /** 受理通道 */
  channel: string;
  /** 时效承诺 */
  sla: string;
}

const DEFAULT_SLA = "受理后 1 个工作日内联系您,一般 3 个工作日内出结果";

const RULES: Record<string, ApprovalRule> = {
  "card.limit_adjust": {
    capability: "card.limit_adjust",
    lane: "信用卡额度调整",
    materials: [
      "本人有效身份证件(在 App 内人脸核身,部分情形需柜面核验原件)",
      "近 6 个月收入或资产证明(工资流水 / 纳税记录 / 金融资产截图,任一即可)",
      "提额用途说明(如装修、教育、医疗,一句话即可)",
      "如为经营性用途:营业执照或经营流水",
    ],
    channel: "手机银行 App「我的 → 卡片 → 额度管理 → 上传材料」;也可由人工坐席代为上传",
    sla: DEFAULT_SLA,
  },
  "card.unblock": {
    capability: "card.unblock",
    lane: "交易限制解除",
    materials: [
      "本人有效身份证件",
      "限制涉及的交易凭证(合同、发票或订单截图)",
      "如为可疑交易核实:交易对手与用途说明",
    ],
    channel: "手机银行 App「卡片 → 限制说明 → 提交解除材料」",
    sla: DEFAULT_SLA,
  },
  "card.new_application": {
    capability: "card.new_application",
    lane: "新卡审批",
    materials: [
      "本人有效身份证件(申请时已完成核身)",
      "工作或收入信息(单位名称、月收入区间)",
      "★ 学生卡 / 特定卡种需补充学籍或资质材料,以审核通知为准",
    ],
    channel: "手机银行 App「卡片 → 办新卡」提交,银行审核后寄卡",
    sla: "审核 1–2 个工作日,制卡寄送 5–12 个工作日",
  },
  "wealth.purchase": {
    capability: "wealth.purchase",
    lane: "理财申购(大额/超风险等级)",
    materials: [
      "本人有效身份证件",
      "已完成且在有效期内的风险承受能力测评(一年一评)",
      "超出自身风险等级时:《风险不匹配确认书》(可在对话中直接签署)",
    ],
    channel: "由您本人在手机银行 App 完成签署与确认;超限额部分由理财经理人工复核",
    sla: "签署与确认即时生效;人工复核部分 T+1 反馈",
  },
  "transfer.submit": {
    capability: "transfer.submit",
    lane: "转账(触发风控或超限额)",
    materials: [
      "本人有效身份证件",
      "如被风控拦截:收款人关系说明、转账事由与资金来源说明",
      "如为代付/经营性转账:合同或订单凭证",
    ],
    channel: "手机银行 App「安全中心 → 交易核实」提交;或由反诈专员电话核实",
    sla: "核实通过后即时放行;未能核实的将维持拦截",
  },
  "collection.create": {
    capability: "collection.create",
    lane: "AA 收款(涉及他人资金)",
    materials: ["本人有效身份证件", "分摊事由与参与人清单(对话中已收集)"],
    channel: "手机银行 App「AA 收款」",
    sla: DEFAULT_SLA,
  },
  "card.report_loss": {
    capability: "card.report_loss",
    lane: "挂失与补卡",
    materials: ["本人有效身份证件", "补卡方式选择(换号 / 保留原号,对话中已收集)"],
    channel: "挂失即时生效;补卡由银行制卡侧处理",
    sla: "挂失即时生效;补卡 5–12 个工作日到手",
  },
};

/**
 * 取某个能力的人工审批规则;没有登记则该事项不需要人工审批。
 *
 * ★ "没有登记"不等于"Agent 可以随便办":
 *   能不能办由策略引擎裁决(handoff / deny),这里只管"一旦要人工审,
 *   客户需要准备什么"。两件事分开,规则才不会被写重。
 */
export function approvalRuleFor(capability: string): ApprovalRule | null {
  return RULES[capability] ?? null;
}

/** 面向客户的一句话:已转人工审批 + 材料清单 */
export function renderHandoffNotice(rule: ApprovalRule): string {
  const lines: string[] = [];
  lines.push(`已转人工审批:${rule.lane}`);
  lines.push("");
  lines.push("请提交以下材料(提交后由银行人工审核,不是我在办):");
  rule.materials.forEach((m, i) => lines.push(`  ${i + 1}. ${m}`));
  lines.push("");
  lines.push(`提交入口:${rule.channel}`);
  lines.push(`时效:${rule.sla}`);
  lines.push("审核期间这笔不会生效,也不会占用您的额度或资金。");
  return lines.join("\n");
}
