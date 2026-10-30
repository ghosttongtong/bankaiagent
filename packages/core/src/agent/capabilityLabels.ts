/**
 * 能力名 → 面向用户的中文说法。
 *
 * ★ 为什么单独成一个模块,而不是留在 orchestrator 里当私有函数:
 *   这张表必须**覆盖全部能力**,而它原来只登记了 26 个 —— 挂失、补卡、提额、
 *   解限、理财购买/赎回这些**真正会出现在"待办"里的**操作全都缺,
 *   用户在我们的 App「待办」列表里看到的就是一句含糊的「一项待确认的操作」。
 *   (原注释只提到"不能把 transfer.cancel_schedule 原样显示给用户",
 *    这个底线兜住了;但漏掉的是另一半 —— 兜底说法太含糊,等于没说。)
 *
 *   放在独立模块里,才能被"注册表里每个能力都必须有中文说法"的断言直接检查
 *   (见 redteam.test.ts「★ 能力名到人话:注册表里不能有说不清的能力」)。
 *   留在 orchestrator 里就只能靠人肉记忆同步,这张表已经漏过一次了。
 *
 * ★ 兜底仍然保留(``一项待确认的操作``):任何**未登记**的能力名都不会把
 *   内部英文标识抛给用户。断言是防"忘记登记",兜底是防"真的漏了"。
 */

/**
 * 全部会面向客户出现的能力的中文说法。
 *
 * 覆盖口径:注册表里的**每一个**能力,包含只读能力 ——
 * 只读能力同样会出现在流程回溯(flowTrace)与操作状态(operationStatus)里,
 * 客户问"刚才那步是什么"时不该得到一句含糊话。
 */
const CAPABILITY_LABELS: Record<string, string> = {
  // ---- 转账 ----
  "transfer.submit": "转账",
  "transfer.preview": "转账试算",
  "transfer.create_schedule": "定时转账设置",
  "transfer.cancel_schedule": "取消定时转账",
  "transfer.cancel": "撤销转账",
  "transfer.list_schedules": "定时转账查询",
  // ---- AA 收款 ----
  "collection.create": "AA 收款",
  "collection.remind": "AA 催收提醒",
  "collection.list": "AA 收款记录",
  // ---- 记账与账单 ----
  "note.create": "记账备注",
  "note.list": "备注记录",
  "account.report": "账单报告",
  "account.detect_anomalies": "异常交易检查",
  "account.detect_recurring": "定期支出识别",
  "account.cashflow": "收支分析",
  "account.insights": "账单洞察",
  "account.payday_brief": "发薪分配清单",
  "account.health_label": "财务健康标签",
  "account.budget_plan": "预算规划",
  "account.analyze_spending": "消费分析",
  "account.list_balances": "余额查询",
  "account.list_transactions": "交易明细查询",
  "document.compare": "文档比对",
  // ---- 安全凭证 ----
  "security.change_phone": "更换绑定手机号",
  "security.change_password": "修改密码",
  // ---- 订阅代扣 ----
  "subscription.scan": "订阅代扣识别",
  "subscription.list": "续费提醒",
  "subscription.detail": "订阅详情",
  "subscription.cancel": "取消订阅代扣",
  // ---- 卡片 ----
  "card.list": "我的卡片",
  "card.detail": "卡片详情",
  "card.report_loss": "挂失",
  "card.replace": "补卡",
  "card.activate": "激活新卡",
  "card.new_application": "信用卡申请",
  "card.limit_adjust": "额度调整",
  "card.limit_eligibility": "提额资格评估",
  "card.limit_status": "提额进度查询",
  "card.restrictions": "交易限制查询",
  "card.unblock": "解除交易限制",
  // ---- 收款人 ----
  "payee.search": "收款人查询",
  "payee.check_deliverable": "收款人可到账性核验",
  // ---- 理财 ----
  "wealth.list_products": "理财产品列表",
  "wealth.product_detail": "理财产品详情",
  "wealth.compare": "理财产品对比",
  "wealth.risk_assess": "风险测评",
  "wealth.purchase": "理财购买",
  "wealth.redeem": "理财赎回",
  "wealth.holdings": "持仓查询",
  "wealth.rollover_plan": "到期续接方案",
  "wealth.rollover_choose": "登记续接选择",
  // ---- 制度问答与历史记录 ----
  "policy.search": "制度条款查询",
  "memory.search": "历史记录查询",
  // ---- 跨场景事件联动 ----
  "cross_scene_event_planning": "跨场景联动方案",
  "event.list": "关键事件清单",
  "event.register": "登记关键事件",
  "event.fund_step": "联动方案·资金操作",
  "event.external_step": "联动方案·外部服务操作",
};

/**
 * 刻意**不给**客户看法的能力:内部探针。
 *
 * 它只为测试/诊断而注册,永远不会出现在待办、流程回溯或操作状态里。
 * 断言里明确列出这个例外,比让断言"默认放过所有只读能力"更安全 ——
 * 后者会在新增能力时静默放过。
 */
export const INTERNAL_ONLY_CAPABILITIES: ReadonlySet<string> = new Set(["internal.risk_probe"]);

/** 未登记能力的兜底说法:含糊,但绝不出卖内部标识 */
export const UNKNOWN_CAPABILITY_LABEL = "一项待确认的操作";

/** 能力名 → 面向用户的中文说法(未登记时给中性说法) */
export function capabilityLabel(name: string): string {
  return CAPABILITY_LABELS[name] ?? UNKNOWN_CAPABILITY_LABEL;
}

/** 供断言与自查使用:当前已登记说法的能力名 */
export function labeledCapabilityNames(): string[] {
  return Object.keys(CAPABILITY_LABELS);
}