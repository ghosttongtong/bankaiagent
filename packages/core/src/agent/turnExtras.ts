/**
 * 回合附加信息(Turn Extras)—— 交互体验打磨的四件事的**数据契约**
 *
 * 这四项能力全部是"在既有主链路上加一层",而不是改业务逻辑:
 *
 *   1. **办理流程可视化**(FlowTrace)
 *      把"这一轮 Agent 到底做了哪几步、每一步是谁在执行"讲清楚。
 *      刻意不是"演示动画",而是**从审计链派生出来的事实**:
 *      同一个 traceId 下真实发生过的审计事件,翻译成人话与视觉步骤。
 *      因此界面上看到的流程与审计里能查到的证据**必然一致** ——
 *      不存在"界面显示办好了、审计里没有"这种自相矛盾。
 *
 *   2. **来源标注**(SourceCitation)
 *      凡是金额、规则、时效,都要能回答四个问题:
 *      这个数字**从哪来**(source)、**算谁的**(subject)、**什么时候有效**(effective)、
 *      **怎么算出来的**(calculation)。银行场景里"800 元"与"800 元,来自信贷系统,
 *      截至 2026-10-16 09:12,按 6 个月用卡记录的月均消费计算"是两种完全不同的可信度。
 *
 *   3. **个性化主动建议**(ProactiveSuggestion)
 *      记住客户办过什么,在**合适时机**给一条可点的建议。
 *      规则是确定性的(纯函数),模型不参与 —— 与全项目"模型不做裁决"的立场一致。
 *
 *   4. **自主执行 vs 人工审批**(FlowStep.lane)
 *      每一步都显式标注归谁:Agent 自主办(auto)、必须客户本人授权(customer)、
 *      必须银行人工审批(human_review)。**这条区分是印在步骤上的**,不是一句口头说明。
 *
 * ★ 为什么类型单独放一个文件:
 *   编排器(orchestrator.ts)已经有一万余行,再往里塞视觉层的契约会让它更难维护。
 *   这里只放"能跨层传的结构",渲染逻辑在 flowTrace.ts,持久化在 server 侧。
 */

import type { Channel } from "../types.ts";

// ============================================================================
// 来源标注
// ============================================================================

/** 数字/规则的口径与出处 */
export interface SourceCitation {
  /** 稳定 ID,供界面去重与审计引用 */
  id: string;
  /** 面向客户的一句话主题,如「本月支出合计 3,120.50 元」或「R-RISK-SCORE 风险评分」 */
  topic: string;
  /** 数据来源(系统名/规则库/能力名),如 `银行核心·交易流水` `策略引擎 v1` */
  source: string;
  /** 主体:这条数据或规则约束的是谁 —— 客户本人 / 本笔交易 / 银行侧 */
  subject: string;
  /** 口径时效:如「2026-10-01 ~ 2026-10-16」「实时查询」「规则版本 2026-01」 */
  effective: string;
  /** 抓取/生效时点(毫秒时间戳,便于界面显示"截至 09:12") */
  asOf: number;
  /** 计算过程:逐段拼成算式,如 ["餐饮 1,240.00", "交通 380.50", "合计 1,620.50"] */
  calculation?: string[];
  /** 补充说明(如"仅含已清算交易") */
  note?: string;
  /** 该条目是规则裁决还是数据 */
  kind: "data" | "rule";
}

/**
 * 把一条引用渲染成面向客户的一行。
 *
 * ★ 只在这里渲染一次,界面上与文本渠道里用的是同一份文字 ——
 *   否则 IM 里的话术与 App 里的口径会慢慢漂移(这是多渠道产品最常见的腐坏方式)。
 */
export function formatCitationLine(c: SourceCitation): string {
  const parts = [`来源:${c.source}`, `主体:${c.subject}`, `时效:${c.effective}`];
  return `【${c.topic}】${parts.join(" · ")}${c.kind === "rule" ? "(规则)" : ""}`;
}

// ============================================================================
// 办理流程(FlowTrace)
// ============================================================================

/**
 * 这一步归谁办。
 *
 * ★ 这四个值是本需求(区分自主执行与人工审批)的**实现载体**:
 *   它不是文案,而是流程节点上的一个字段,由服务端判定、界面据实渲染。
 */
export type FlowLane =
  /** Agent 自主执行:只读查询、分析,或系统内已获授权的写操作 */
  | "auto"
  /** 需要客户本人授权:资金变动、签约、申购等 —— 客户不确认,Agent 不会执行 */
  | "customer"
  /** 需要客户本人完成安全动作:人脸/指纹、短信验证码(凭证侧,Agent 碰不到) */
  | "customer_auth"
  /** ★ 已转人工审批:Agent 不代办,由银行人工审核处理 */
  | "human_review"
  /** 被系统拒绝 / 无法办理 */
  | "blocked";

export type FlowStepStatus = "done" | "active" | "waiting" | "failed" | "skipped";

export interface FlowStep {
  id: string;
  /** 人话:这一步做了什么 */
  label: string;
  /** 补充证据:如"命中 R-FIRST-PAYEE 规则""回执验签通过" */
  detail?: string;
  status: FlowStepStatus;
  lane: FlowLane;
  /** 该步骤的审计事件类型(界面可据此跳转审计面板) */
  auditType?: string;
  /** 发生时刻 */
  ts: number;
}

export interface FlowTrace {
  /**
   * ★ 业务线程 ID —— 界面靠它把"同一次办理的多次交互"合并成**一张会动的卡**。
   *
   * 资金类操作天然跨两轮:第 1 轮"等你确认"、第 2 轮办结。
   * 若每轮都新画一张卡,客户会看到上面一张永远停在"进行中"、下面又冒出一张"已办结" ——
   * 这比没有流程更糟:它会让人以为有两笔业务,或者以为第一笔没办成。
   * 同一 threadId 的回合,界面应当**原地更新**同一张卡。
   *
   * 取值规则(由编排器给出):
   *   · 一句新请求        → 本轮 traceId
   *   · 对某个待确认动作的确认/授权 → **那个动作的 traceId**(于是续上同一条线程)
   */
  threadId: string;
  /** 流程标题,如「转账汇款 · 给老妈转 500 元」 */
  title: string;
  /** 稳定流程键,供"常用流程"识别(不同于模板 ID,它是行为指纹) */
  flowKey: string;
  steps: FlowStep[];
  /** 一句话总结,如「已自动办结(2 步只读查询)」/「等你确认后才执行」/「已转人工审批」 */
  summary: string;
  /** 是否还需要客户动作 */
  awaitingCustomer: boolean;
  /** 是否已转人工审批 */
  handedToHuman: boolean;
  /** 是否可保存为常用流程(只读查询不值得存) */
  saveable: boolean;
  /** 可保存时的模板(由服务端派生,含脱敏后的字段) */
  template?: SavedFlowTemplate;
}

// ============================================================================
// 可视化块(Visual Block)
// ============================================================================

/**
 * ★ 有些结论"说一遍不如摆出来"。
 *
 *   多份材料的矛盾点、重扫的成本与风险、误报撤回的前后对比 ——
 *   这三件事的共同点是:**关系**比**数值**重要。
 *   用一段文字描述"合同写 12.8 万、发票写 13.8 万,差 1 万",
 *   客户得自己在脑子里对齐两份材料;画成两列对照表,矛盾处一高亮,几乎不用读。
 *
 *   所以这里定义的是"结构化可视块",由服务端给出**要显示什么**、
 *   界面只负责**怎么画**(与流程卡同一条边界:前端不做业务判断)。
 */
export interface DocDiffCell {
  docId: string;
  text: string;
  /** 该格与同行的其它格不一致 */
  differs: boolean;
}

export interface DocDiffRow {
  /** 字段名,如「合同金额」 */
  label: string;
  severity: "conflict" | "warn" | "ok";
  values: DocDiffCell[];
  /** 一句话说明差异意味着什么(面向客户,不含内部术语) */
  note?: string;
}

/** 材料比对:多列对照 + 矛盾高亮 */
export interface DocDiffVisual {
  kind: "doc_diff";
  title: string;
  documents: Array<{ id: string; label: string; kindLabel: string }>;
  rows: DocDiffRow[];
  conflictCount: number;
  /** 客户最需要知道的一句话结论 */
  verdict: string;
  /** 建议动作(可点,由界面直接发送) */
  actions?: Array<{ label: string; say: string }>;
}

/** 成本/风险权衡:两条评分 + 决策 */
export interface ReviewPlanVisual {
  kind: "review_plan";
  title: string;
  /** 机器结论,界面据此配色 */
  decision: "rescan" | "inspect_gaps" | "rescan_incremental" | "scan_first";
  decisionLabel: string;
  rescanCost: { score: number; factors: string[] };
  omissionRisk: { score: number; factors: string[] };
  gaps: string[];
  actions: Array<{ label: string; say: string }>;
}

/** 误报撤回:证据 → 撤回 → 仍需复核 */
export interface RetractionVisual {
  kind: "retraction";
  title: string;
  evidence: string;
  withdrawn: Array<{ title: string; reason: string }>;
  stillOpen: Array<{ title: string; reason: string; severity: string }>;
  /** 未受影响(已确认为正常)的条数 */
  unaffectedCount: number;
  actions?: Array<{ label: string; say: string }>;
}

export type VisualBlock = DocDiffVisual | ReviewPlanVisual | RetractionVisual;

// ============================================================================
// 常用流程模板
// ============================================================================

export interface TemplateParam {
  /** 参数名(与能力入参键对应,便于生成自然语言) */
  key: string;
  /** 面向客户的标签,如「金额」 */
  label: string;
  /** 是否为每次都要填的必填参数 */
  required: boolean;
  /** 最近一次使用过的值(用于预填) */
  lastValue?: string;
  /** 示例值 */
  example?: string;
}

/**
 * 常用流程模板。
 *
 * ★ 这里存的是**意图模板**而不是"一次执行的录像":
 *   「给老妈转账」是模板,金额是参数 —— 所以它可以被反复用。
 *   如果把金额也冻进去,那存下来的就只是一笔历史流水,下次还得整句重说一遍,
 *   所谓"下次直接调用"就是假的。
 *
 * ★ 敏感字段(账号、证件号)在派生时就已剥离,模板里只留可展示的字段。
 */
export interface SavedFlowTemplate {
  templateId: string;
  /** 展示名,如「给老妈转账」 */
  name: string;
  /** 能力名(仅供服务端使用;界面上不展示,避免前端出现能力名判断) */
  capability: string;
  /** 自然语言模板,如「给 老妈 转 {金额} 元,备注 {备注}」 */
  sentence: string;
  /** 参数槽位 */
  params: TemplateParam[];
  /** 不随每次变化的固定部分(如收款人、备注),用于生成语句 */
  fixed: Record<string, string>;
  createdAt: number;
  lastUsedAt?: number;
  useCount: number;
}

// ============================================================================
// 个性化主动建议
// ============================================================================

export interface ProactiveSuggestion {
  id: string;
  /** 建议的文案(面向客户,直接可展示) */
  text: string;
  /** 为什么现在提这条 —— 必须可解释,否则就是骚扰 */
  reason: string;
  /** 点击后直接发送的自然语言 */
  say: string;
  /** 规则 ID(与策略规则一样可审计) */
  ruleId: string;
  /** 排序权重,越大越先展示 */
  weight: number;
  /** 建议来源:规则引擎 / 常用流程 / 客户历史 */
  origin: "rule" | "saved_flow" | "history";
}

/**
 * 主动建议的输入事实(由宿主机从银行侧与历史记录组装)。
 *
 * ★ 刻意是一个**扁平的快照**:建议规则是纯函数,
 *   不反向查询银行核心,也不访问会话 —— 因此可单测、可复现。
 */
export interface SuggestionFacts {
  customerId: string;
  displayName: string;
  now: number;
  /** 本月已发生支出合计 */
  monthExpense: number;
  /** 本月已发生支出笔数 */
  monthExpenseCount: number;
  /** 活期可用余额合计 */
  availableBalance: number;
  /** 已保存的常用流程 */
  savedFlows: Array<{ templateId: string; name: string; lastUsedAt?: number; useCount: number; say: string }>;
  /** 最近 30 天用过的能力(去重,最近优先) */
  recentCapabilities: string[];
  /** 本次会话里已完成的业务(能力名按时间顺序) */
  sessionCapabilities: string[];
  /** 客户是否已做过风险测评 */
  wealthAssessed: boolean;
}

/**
 * 主动建议端口。
 *
 * ★ 为什么是端口而不是内置规则:
 *   规则要用到"本月花了多少""余额还有多少"这类事实,它们属于银行侧数据,
 *   core 不该直接去查(否则 core 就依赖了具体的数据源)。
 *   宿主(server)组装好事实快照注入进来,core 只负责"在合适的时机问一句"。
 */
export interface SuggestionPort {
  suggest(input: SuggestionFacts): Promise<ProactiveSuggestion[]>;
}

// ============================================================================
// 编排器收集器
// ============================================================================

/**
 * 本轮的可变收集器。
 *
 * 为什么需要它:来源标注与流程步骤是在**链路各处**产生的
 * (能力执行里、策略裁决后、确认卡生成时),而回复是最后才拼出来的。
 * 收集器就是这中间的那只"篮子" —— 由编排器在每轮开始时创建,
 * 结束后交给装饰器生成面向客户的部分。
 */
export interface TurnExtras {
  traceId: string;
  turnId: string;
  channel: Channel;
  /** 本轮的流程键(如 transfer.submit) */
  flowKey: string;
  /** 本轮涉及的能力(按调用顺序去重) */
  capabilities: string[];
  citations: SourceCitation[];
  hasMonetary: boolean;
  hasRuleDecision: boolean;
  /** 本轮是否已转人工审批 */
  handedToHuman: boolean;
  /** 人工审批所需的材料清单(转人工时给出,客户据此提交) */
  handoffMaterials: string[];
  /** 人工审批的受理渠道与时效说明 */
  handoffChannel?: string;
  /** 本轮的确认卡(用于派生常用流程模板) */
  confirmCard?: { title: string; fields: Array<{ label: string; value: string }> };
  /** 本轮实际执行成功的能力 */
  executedCapability?: string;
  /**
   * ★ 本轮是否**真的执行了**能力(而不只是展示了确认卡)。
   *
   * 这个字段是"常用流程可以被记住"的前提:
   *   只有办成过的事才允许存成常用流程 —— 存一个从没办成的套路,
   *   客户下次点一下还是办不成,那功能就是坏的。
   */
  executed: boolean;
  /** 是否发生了不可逆/资金类实际执行 */
  moneyMoved: boolean;
  /** 本轮产生的个性化建议(由 suggestionPort 计算,回合出口渲染) */
  suggestions?: ProactiveSuggestion[];
  /**
   * ★ 业务线程 ID(界面据此原地更新同一张流程卡)。
   *
   * 默认等于本轮 traceId;当本轮是对某个待确认动作的确认/授权时,
   * 编排器会把它改成**那个动作的 traceId** —— 于是"等你确认 → 已办结"
   * 是同一张卡的两帧,而不是两张各说各话的卡。
   */
  flowThreadId?: string;
  /** 本轮是否属于"接续上一轮同一业务"(而非一笔新业务) */
  flowContinuation?: boolean;
  /**
   * ★ 本渠道是否**同时具备富卡片与交互按钮**(App / Web)。
   *
   * 它决定回复文本要不要带"流程/出处/建议的文字版":
   *   富渠道已经有流程卡、来源折叠块、建议气泡 —— 再在文本里重复一遍,
   *   就是同一件事说两遍,把回复撑到需要滚三屏。
   *   文字渠道(IM/语音)没有这些控件,**必须**由文本承载。
   */
  richUi: boolean;
  /** 本轮要单独摆出来的可视块(材料比对 / 复核决策 / 误报撤回) */
  visual?: VisualBlock;
}

export function createTurnExtras(input: {
  traceId: string;
  turnId: string;
  channel: Channel;
  flowKey?: string;
  richUi?: boolean;
}): TurnExtras {
  return {
    traceId: input.traceId,
    turnId: input.turnId,
    channel: input.channel,
    flowKey: input.flowKey ?? "unknown",
    capabilities: [],
    citations: [],
    hasMonetary: false,
    hasRuleDecision: false,
    handedToHuman: false,
    handoffMaterials: [],
    executed: false,
    moneyMoved: false,
    flowThreadId: input.traceId,
    richUi: input.richUi ?? false,
  };
}

/** 幂等追加引用(同一个 topic 只保留第一条,避免重复刷屏) */
export function pushCitation(extras: TurnExtras, citation: SourceCitation): void {
  if (extras.citations.some((c) => c.id === citation.id)) return;
  extras.citations.push(citation);
}
