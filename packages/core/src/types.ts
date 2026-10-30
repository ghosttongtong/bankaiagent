/**
 * 银行 AI 智能体 —— 核心领域契约
 *
 * 设计不变量(Invariants)—— 全系统必须遵守,任何实现不得绕过:
 *   I1. 模型永不做裁决:LLM 只负责理解与规划;是否放行由确定性策略引擎决定。
 *   I2. 模型永不持有凭证:凭证只在执行器内部、单次调用生命周期内存在。
 *   I3. 数字必须来自工具:响应中任何金额/余额/收益必须携带 sourceTool 引用。
 *   I4. 不可逆操作必须载荷冻结:用户确认的内容与最终执行的内容是同一份冻结载荷。
 *   I5. 每个副作用节点独立裁决:DAG 中不继承前置节点的许可。
 *   I6. 一切外部输入均不可信:交易备注、收款人姓名、对账单、网页均为注入载体。
 *   I7. 全链路可回放:任一时点的裁决可凭审计日志完整复现。
 */

import type { z } from "zod";

import type {
  FlowTrace,
  ProactiveSuggestion,
  SourceCitation,
  TurnExtras,
  VisualBlock,
} from "./agent/turnExtras.ts";

// ============================================================================
// 一、渠道层
// ============================================================================

/** 接入渠道。渠道只是入口,核心逻辑不为任何渠道写特例。 */
export type Channel = "app" | "im" | "web" | "voice";

/**
 * 渠道能力。策略引擎把渠道风险与能力作为一等输入:
 * IM 消息可截图、可转发、会话易被接管,因此高风险操作必须在 IM 中降级处理。
 */
export interface ChannelCapabilities {
  /** 渠道固有风险等级 */
  risk: "low" | "medium" | "high";
  /** 是否支持富卡片渲染(否则降级为纯文本 + 编号选项) */
  richCard: boolean;
  /** 是否支持生物识别(指纹/面容) */
  biometric: boolean;
  /** 是否支持一次性深链跳转(用于"跳回 APP 完成强验证") */
  deepLink: boolean;
  /** 是否支持交互式按钮 / 快捷回复 */
  interactive: boolean;
}

/**
 * 统一消息信封。所有渠道的入站消息都必须规范化为此结构,
 * 出站消息按渠道能力渲染。核心逻辑只认这个结构。
 */
export interface MessageEnvelope {
  channel: Channel;
  /** 渠道内用户标识(如 Telegram user id) */
  channelUserId: string;
  /** 绑定后的银行客户主身份(经渠道绑定流程确认) */
  customerId: string;
  text: string;
  /** 渠道附带的结构化动作(按钮点击、卡片确认等),非文本输入时为非空 */
  action?: ChannelAction;
  /** 渠道相关元数据,如设备指纹、IP 归属地 */
  channelMeta?: Record<string, unknown>;
  /** 会话 ID。同一次连续对话共用一个,用于上下文依赖解析("还是上次那个") */
  sessionId?: string;
  /** 幂等:同一入站消息重放不得产生重复副作用 */
  messageId: string;
  ts: number;
  /**
   * ★ 入站请求携带的中断意图(可选)。
   *
   * 谁会带:网关收到客户端主动断开 / 上游超时 / 运营强制中止时,把意图
   * 随请求一起交进来。它是**数据**(一个快照),不是可以随时杀执行的钩子 ——
   * 编排器把它放进 ExecutionContext.cancellation,由银行核心的**提交边界**
   * 读一次:提交点之前 = 干净中止;提交点之后 = 走补偿。
   *
   * 为什么不做成 AbortSignal:资金操作被中途杀掉会留下"钱扣了、状态未知",
   * 那是最坏的一种状态。这个系统的立场是"先定义提交点,再谈取消"。
   */
  cancellation?: CancellationState;
}

/** 渠道传来的结构化动作(点击"确认"/"取消"/选择候选收款人) */
export interface ChannelAction {
  kind: "confirm" | "cancel" | "select" | "deep_link_return" | "text";
  /** 被操作对象的引用 ID(如待确认的转会话 ID) */
  refId?: string;
  /** 选择类动作的取值(如候选收款人 ID) */
  value?: string;
  /** 强验证回执(由原生安全流程签名,Agent 只做转交校验) */
  authProof?: AuthProof;
}

// ============================================================================
// 二、风险分级(对应 1.docx 权限分级机制 + 扩展)
// ============================================================================

/**
 * 强验证回执。
 *
 * 关键设计:Agent **不实现**验证逻辑,也不接触生物特征数据。
 * 验证在原生安全环境(手机银行 App / U 盾 / 短信网关)中完成,
 * 由可信方签发这份回执;Agent 只负责转交校验。
 *
 * 这样可以回答"Agent 被攻破能否伪造验证"这个问题:不能 ——
 * 它没有签发密钥,回执在服务端以非对称签名验真。
 */
export interface AuthProof {
  /** 使用的验证方式 */
  method: "biometric" | "sms_otp" | "usb_key" | "password" | "trusted_device";
  /** 签发方标识 */
  issuer: string;
  /** 绑定到的载荷哈希 —— 防止验证通过后被替换载荷(TOCTOU) */
  boundPayloadHash: string;
  issuedAt: number;
  expiresAt: number;
  /** 签名。生产环境为可信方的非对称签名;演示环境为 HMAC */
  signature: string;
  /** 一次性随机数,防重放 */
  nonce: string;
}

/**
 * 执行分级 —— 对应文档的绿/黄/红,并扩展出阻断级。
 *
 * 演进原则:凡"安全方向"的操作(降额、冻结、取消)降级;
 *          凡"扩权方向"的操作(提额、新增、变更凭证)升级。
 */
export type Tier =
  /** 绿:自动执行,无副作用,仅限本人数据域 */
  | "auto"
  /** 黄:用户明确确认后执行,载荷冻结 + 展示详情 */
  | "confirm"
  /** 红:多因子强验证(人脸/短信/U盾/可信设备) */
  | "strong_auth"
  /** 黑:阻断级,Agent 不得经手,仅引导至官方原生流程 */
  | "blocked";

/** 策略引擎裁决结果 */
export type PolicyDecision =
  | { effect: "allow"; tier: "auto"; reasons: PolicyReason[] }
  | { effect: "require_confirm"; tier: "confirm"; reasons: PolicyReason[]; confirmSpec: ConfirmSpec }
  | { effect: "require_strong_auth"; tier: "strong_auth"; reasons: PolicyReason[]; authSpec: AuthSpec }
  | { effect: "deny"; tier: "blocked"; reasons: PolicyReason[]; userMessage: string; guidance?: Guidance }
  | { effect: "handoff"; reasons: PolicyReason[]; handoffSpec: HandoffSpec };

/** 裁决理由 —— 可解释性的载体,审计与答辩都用它 */
export interface PolicyReason {
  /** 稳定规则 ID,如 R-FIRST-PAYEE-ESCALATE */
  ruleId: string;
  /** 人类可读说明(面向审计员/评委,不是面向终端用户) */
  message: string;
  /** 该规则造成的分级变化 */
  effect?: "escalate" | "deescalate" | "deny" | "pass";
  /** 规则命中时的证据(金额、名单项、画像偏离度等) */
  evidence?: Record<string, unknown>;
}

export interface ConfirmSpec {
  /** 冻结载荷的哈希。用户确认的是这份哈希,执行时校验,防 TOCTOU */
  payloadHash: string;
  /** 面向用户的人话版详情(不是 JSON dump) */
  humanReadable: string;
  /** 富卡片结构(渠道不支持富卡片时,渲染器会降级为文本+编号) */
  card: ConfirmCard;
  /** 确认有效期(毫秒)。过期需重新发起 */
  ttlMs: number;
}

export interface ConfirmCard {
  title: string;
  /** 关键字段:收款人 / 金额 / 手续费 / 到账时间 / 备注 —— 逐项展示,禁止折叠 */
  fields: Array<{ label: string; value: string; emphasis?: boolean }>;
  /** 不可逆操作的明确警告文案 */
  warning?: string;
  /** 可撤销窗口说明(如有) */
  reversibility?: string;
}

export interface AuthSpec {
  /** 允许的验证方式,按强度排序 */
  methods: Array<"biometric" | "sms_otp" | "usb_key" | "password" | "trusted_device">;
  /** 本次强验证要求的最低方式(可组合) */
  required: Array<"biometric" | "sms_otp" | "usb_key" | "password" | "trusted_device">;
  /** 一次性动作令牌:强验证通过后签发,绑定到冻结载荷哈希,单次有效 */
  actionToken?: string;
  ttlMs: number;
  /**
   * ★ 被授权的操作详情。
   *
   * 为什么必须带着它:客户有权在**授权之前**看清自己授权了什么。
   * 只显示"请完成人脸识别"而不显示转账金额与收款人,在银行场景既不合理也不合规 ——
   * 用户可能在完全不知道验证目的的情况下完成了授权。
   */
  subject?: ConfirmCard;
  /** 当前渠道无法完成强验证时的替代路径 */
  fallbackGuidance?: Guidance;
}

export interface HandoffSpec {
  reason: string;
  /** 转人工的紧迫度 */
  urgency: "normal" | "high";
  /** 已为用户保全的上下文,人工坐席可见 */
  contextSummary: string;
}

/** 引导用户到安全的地方完成操作(用于 blocked 级) */
export interface Guidance {
  /** 官方原生流程的深链 */
  deepLink?: string;
  /** 面向用户的人话说明 */
  message: string;
}

// ============================================================================
// 三、能力注册表(Capability Registry)
// ============================================================================

/**
 * 能力 —— Agent 可执行的唯一原子单位。
 *
 * 关键设计:能力不是"随便调 API 的自由",而是有限、有 Schema、有幂等键、
 * 有可逆性标记的原子操作。Agent 无法执行注册表之外的动作。
 */
export interface CapabilitySpec<
  TInput extends z.ZodTypeAny = z.ZodTypeAny,
  TOutput extends z.ZodTypeAny = z.ZodTypeAny,
> {
  /** 稳定名,如 transfer.create_draft。模型只能从这个枚举里选 */
  name: string;
  /** 面向模型的一句话说明(进系统提示词,必须精确、无歧义) */
  description: string;
  /** 入参 Schema。执行前强制校验,模型输出不合法直接拒绝 */
  input: TInput;
  /** 出参 Schema。用于 I3(数字必须来自工具)的字段级校验 */
  output: TOutput;

  /** 副作用等级 —— 决定是否需要独立裁决与确认 */
  sideEffect: "none" | "reversible" | "irreversible";
  /** 是否为资金操作(资金操作永不继承前置许可) */
  moneyMovement: boolean;
  /** 幂等语义:如何构造幂等键 */
  idempotency: "none" | "required";

  /** 该能力的**基线**分级。注意:实际分级由策略引擎动态升降,此为兜底默认 */
  baseTier: Tier;

  /** 是否为只读能力(只读能力限定在客户自身数据域) */
  readOnly: boolean;
  /**
   * 是否允许自动执行(无需用户确认)。
   *
   * ★ 只有"低风险写操作"才应设为 true,例如客户侧记账批注 ——
   *   它不移动资金、不改动银行流水,只是给客户自己的记录加一条说明。
   *   强制要求确认会让"帮我记一下"这种诉求变得很烦。
   *
   *   资金操作与任何改动账户状态的操作**必须保持 false**。
   *   注意:这不同于 readOnly —— readOnly 限定在"只读取本人数据",
   *   而 autoExecutable 表达的是"虽然写入,但风险低到不需要确认"。
   */
  autoExecutable?: boolean;
  /** 敏感字段路径:这些字段在进入模型上下文前必须脱敏 */
  sensitiveFields?: string[];
  /** 输出中的金额字段路径 —— I3 校验用 */
  monetaryFields?: string[];

  /** 前置条件:不满足则能力不可用(如"未绑定可信设备则不可强验证") */
  preconditions?: Array<{
    id: string;
    description: string;
    check: (ctx: ExecutionContext) => boolean;
  }>;

  /**
   * 执行。绝不接收原始凭证,只接收已解析、已校验的参数。
   * I2:凭证由执行器注入,不经过模型。
   */
  execute: (input: unknown, ctx: ExecutionContext) => Promise<CapabilityResult>;
}

export interface CapabilityResult {
  ok: boolean;
  /** 结构化数据。I3:这里的数值是唯一可信来源 */
  data?: unknown;
  error?: { code: string; message: string; retryable: boolean };
}

// ============================================================================
// 四、执行上下文
// ============================================================================

/** 检索到的制度条款(面向能力的只读视图) */
export interface PolicyHitView {
  docId: string;
  /** 文档标题,如「长城信用卡章程」 */
  title: string;
  /** 文档版本,如「2026 版」 */
  version: string;
  clauseId: string;
  clauseTitle: string;
  /** 条款正文原文(由确定性代码原样引用,不经模型改写) */
  text: string;
  effectiveFrom: string;
  issuer: string;
  score: number;
  /** 命中的查询词(解释"为什么是这条") */
  matched: string[];
  coverage: number;
}

/** 制度检索的返回:命中 + 置信度 + 拒答 */
export interface PolicySearchResponse {
  hits: PolicyHitView[];
  confidence: number;
  coverage: number;
  refused: boolean;
  /** 拒答时给客户看的话术(固定,不许模型改写) */
  refusalReason: string | null;
  /** 拒答的内部原因(审计/调试用) */
  refusalCode?: string;
}

/** 客户记忆检索的返回(阶段 2) */
export interface MemorySearchResponse {
  hits: Array<{
    kind: "ledger" | "session" | "note" | "document";
    ts: number;
    text: string;
    score: number;
    opId?: string;
    sessionId?: string;
    traceId?: string;
  }>;
  confidence: number;
}

/**
 * ★ 检索端口(与 BankPort 同风格:依赖注入,core 不读文件、不依赖 bankcore)。
 *
 *   为什么必须走端口而不是让核心直接读语料:
 *   语料从哪来(文件/行内制度库/远程接口)是**部署形态**,不是业务逻辑。
 *   核心只声明"我需要检索",由宿主提供实现 —— 换语料源不用改核心一行。
 */
export interface RetrievalPort {
  searchPolicy(query: string, topK?: number): Promise<PolicySearchResponse>;
  /** 阶段 2:客户记忆检索(台账/会话/备注/材料) */
  searchMemory?(input: { customerId: string; query: string; topK?: number }): Promise<MemorySearchResponse>;
}

/**
 * 执行上下文 —— 由系统构建,模型**不可写**。
 * 模型只能读其中明确暴露给它的部分(见 LlmSafeContext)。
 */
export interface ExecutionContext {
  /** 调用主体:Agent 是独立受限主体,使用受限服务身份,不持有用户凭证 */
  principal: {
    kind: "agent" | "user" | "operator";
    agentId: string;
    /** 受限服务账号,权限远小于客户本人 */
    serviceAccount: string;
  };
  customerId: string;
  channel: Channel;
  channelCapabilities: ChannelCapabilities;
  sessionId: string;
  /** 客户画像(策略引擎的输入,不直接暴露给模型的原始形式) */
  profile: CustomerProfile;
  /** 本次会话已获得的授权令牌 */
  tokens: { actionToken?: string };
  now: number;
  /** 依赖注入的银行核心(便于测试替身) */
  bank: BankPort;
  /** 审计记录器 */
  audit: AuditPort;
  /**
   * ★ 检索端口(可选)。
   *
   * 只有制度/记忆问答需要它。测试替身与 CLI 的局部分支可以不给 ——
   * 届时 policy.search 会如实回答"检索未就绪",而不是编一条条款出来。
   */
  retrieval?: RetrievalPort;
  /** 请求级幂等键 */
  idempotencyKey: string;
  /** 追踪 ID,串联全链路日志 */
  traceId: string;
  /**
   * ★ 本轮的"来源标注"收集篮(可选)。
   *
   * 为什么挂在 ctx 上:数字的产生地在**能力内部**(它才知道自己查了哪张表、
   * 哪段时间、几笔流水),而渲染地在回合出口。中间需要一个收集点,
   * 否则就只能在每个能力里手写一句"数据来源:xxx" —— 那种重复文案迟早会漂移。
   *
   * 它是**可选**的:测试替身、CLI 的局部分支可以不给,系统照常工作
   * (没有出处就只是不显示出处,不会少一个数字)。
   */
  extras?: TurnExtras;
  /**
   * ★ 中断/取消信号(可选)。
   *
   * 为什么是"数据快照"而不是 `AbortSignal`:
   *   给执行器塞一个 AbortSignal 就等于允许**在任意时刻把执行杀掉** ——
   *   资金操作被中途杀掉会留下最坏的状态:"钱扣了,状态未知"。
   *   本项目要的是相反的东西:先定义**提交点**(见 BankPort 的
   *   prepare → commit 两阶段),取消只在提交点之前有效;
   *   提交点之后的"取消"不是中止,而是**补偿**(走已有的 compensateWith)。
   *   所以这里只携带一个只读的意图快照,由提交边界去读它,而不是由它去杀进程。
   *
   * 谁能写:只有编排器(它知道用户说了「取消」/ 上游要求中止);
   *        能力层与模型只能读。它是 ctx 的一部分,因此同样不进冻结载荷、不进哈希。
   */
  cancellation?: CancellationState;
}

/**
 * 取消意图的只读快照。
 *
 * `requested` 一旦为 true 就不会再变回 false —— 语义是"已请求取消",
 * 而不是"当前是否可以取消"。能不能取消由**执行位置**决定:
 * commit 之前 → 干净中止(余额不变);commit 之后 → 不可中止,只能补偿。
 */
export interface CancellationState {
  /** 是否已请求取消 */
  requested: boolean;
  /** 取消的原因(人话,进审计) */
  reason?: string;
  /** 请求取消的时间戳 */
  at?: number;
  /** 触发来源:用户明确说取消 / 上游超时 / 运营干预 / 测试注入 */
  source?: "user" | "timeout" | "operator" | "test";
}

/** 可安全暴露给模型的上下文字段(脱敏后) */
export interface LlmSafeContext {
  customerDisplayName: string;
  channel: Channel;
  /** 当前时间(模型需要它来解析"明天""下周一"这类相对时间) */
  nowIso: string;
  timezone: string;
  /** 货币 */
  currency: string;
}

// ============================================================================
// 材料/凭证(多份材料比对场景)
// ============================================================================

export type DocumentKind = "contract" | "quote" | "invoice" | "receipt" | "statement";

/**
 * 一份客户提交的材料。
 *
 * ★ 为什么要结构化到"字段"级别,而不是存一个 PDF 让模型去读:
 *   比对矛盾点必须是**可复现的判定** —— "合同金额 128,000 ≠ 发票金额 138,000"
 *   这句话要能被审计员照着两份材料逐字核对,而不是"模型觉得不一致"。
 *   字段化之后,比对是纯函数,差异是确定的,连差异金额都能算出来。
 */
export interface CustomerDocument {
  documentId: string;
  kind: DocumentKind;
  kindLabel: string;
  title: string;
  /** 出据方(合同乙方 / 开票方 / 报价方) */
  counterparty: string;
  issuedAt: number;
  /** 参与比对的规范字段。key 必须跨材料对齐,否则比对不到一起 */
  fields: CustomerDocumentField[];
}

export interface CustomerDocumentField {
  /** 规范键,如 amount / paymentTerms / counterparty / deliveryDate / subject */
  key: string;
  label: string;
  value: string | number;
  unit?: string;
  /** 该字段的"可容忍误差"(金额类才有),用于判定"算不算矛盾" */
  tolerance?: number;
}

// ============================================================================
// 五、客户与银行核心端口
// ============================================================================

export interface CustomerProfile {
  customerId: string;
  displayName: string;
  /** 风险偏好与画像基线 —— 用于动态分级 */
  riskProfile: {
    /** 历史单笔转账金额的分位数,用于识别画像偏离 */
    transferAmountP50: number;
    transferAmountP95: number;
    /** 常用收款人 ID 列表(白名单来源之一) */
    frequentPayees: string[];
    /** 常用时段(小时,0-23) */
    activeHours: number[];
  };
  /** 是否已绑定可信设备(强验证前置条件) */
  trustedDeviceBound: boolean;
  /** 客户自定义的风险偏好设置(保守型客户可要求更严格) */
  preferences: {
    /** 超过此金额一律要求强验证(客户自设,只会更严格) */
    alwaysStrongAuthAbove?: number;
    /** 是否开启转账前冷静期提醒 */
    coolDownReminder?: boolean;
  };
  /** 安全策略开关 */
  security: {
    /** 账户是否处于风控限制状态 */
    restricted: boolean;
    /** 限制原因 */
    restrictionReason?: string;
  };
}

/**
 * ★ 两阶段提交的凭据(第 3 项)。
 *
 * 它代表"银行核心已经接受这笔请求,但**还没有动账**"。
 * 这个中间态是刻意暴露出来的:没有它,"取消"就只能靠猜。
 */
export interface PreparedOperation {
  preparedId: string;
  /** 银行核心操作名(稳定标识,审计与排查都用它) */
  op: string;
  customerId: string;
  /** 提交前登记的幂等键 */
  idempotencyKey?: string;
  /** 客户可读的预览(给确认卡/审计看的字段,不含凭证) */
  preview?: Record<string, unknown>;
  /** 相关金额(对账与审计用;非资金操作可为空) */
  amount?: number;
  preparedAt: number;
}

/** commit 的结果:必须能区分「被取消」与「业务失败」与「成功」 */
export interface CommitOutcome {
  ok: boolean;
  /** 是否真的发生了副作用。false 且 cancelled 存在 = 干净中止 */
  committed: boolean;
  /** 提交前被取消(余额/状态未变) */
  cancelled?: { reason: string; source?: string };
  /** 业务返回值(转账回执等) */
  result?: unknown;
  error?: string;
}

/** abort 的结果:已提交过则如实回报,绝不假装撤销 */
export interface AbortOutcome {
  ok: boolean;
  op?: string;
  /** 该 preparedId 已经提交过了 —— 此时只能走补偿,不能假装中止 */
  alreadyCommitted?: boolean;
  /** 被中止的意图 ID(调用方要把它写进审计:否则事后无法回答"中止的是哪一条") */
  preparedId?: string;
  /**
   * ★ 中止原因的**原样回传**。
   *
   *   银行核心没有审计端口(归属信息与链在编排器那一侧),所以它**不写审计**,
   *   只把原因交回调用方。之前这里没有这个字段,而实现的注释却写着"用于审计留痕" ——
   *   口径与实现两张皮(实测被文档核验挑出来)。现在原因必须回传:
   *   调用方把它带进 `execution_cancelled` 事件;谁不写,谁就没留痕,责任清楚。
   */
  reason?: string;
  error?: string;
}

/**
 * 执行作用域:编排器在调用能力前后各设一次,银行核心在提交边界读它。
 *
 * 它**不是**业务入参的一部分(所以不进冻结载荷、不进载荷哈希):
 * 取消信号是"执行期的事实",不是"客户确认过的东西"。
 */
export interface OperationScope {
  /** 取消意图快照(来自 ExecutionContext.cancellation) */
  cancellation?: CancellationState;
  /** 归属信息:审计里要能说清"哪条请求的哪一步被中止了" */
  traceId?: string;
  sessionId?: string;
  customerId?: string;
  planId?: string;
  nodeId?: string;
}

/**
 * 银行核心端口 —— Agent 访问银行系统的唯一通道。
 * 生产环境下这里是对核心系统的受限服务调用;比赛中是模拟账本。
 */
export interface BankPort {
  getAccount(customerId: string, accountId: string): Promise<Account | null>;
  listAccounts(customerId: string): Promise<Account[]>;
  listTransactions(customerId: string, query: TransactionQuery): Promise<Transaction[]>;

  /**
   * 账单分析取数接口。
   *
   * ★ 与 listTransactions 的区别:listTransactions 有 200 条结果护栏
   *   (防诱导批量拉取),而账单分析需要跨 6–12 个月做聚合,200 条不够。
   *   因此银行核心侧提供这个专门的取数口:
   *     · 仍然仅限客户本人账户;
   *     · 时间窗口由调用方限定;
   *     · 用途单一 —— 喂给确定性聚合引擎,原始流水不流向模型。
   *   聚合在银行侧完成,模型只拿到汇总数字 —— 这也是 I3(数字来自工具)
   *   在账单分析场景的落点。
   */
  fetchForAnalysis(customerId: string, query: { from?: number; to?: number }): Promise<Transaction[]>;

  /** 收款人目录:支持按姓名/手机号/别名解析 —— 实体消歧的数据源 */
  searchPayees(customerId: string, query: PayeeQuery): Promise<Payee[]>;
  getPayee(customerId: string, payeeId: string): Promise<Payee | null>;
  /** 别名/昵称映射("老妈" → payeeId) */
  resolveAlias(customerId: string, alias: string): Promise<Payee | null>;
  saveAlias(customerId: string, alias: string, payeeId: string): Promise<void>;

  /** 收款方可达性校验(户名与账号是否匹配) */
  verifyPayeeDeliverable(input: {
    payeeName: string;
    accountNo?: string;
    phone?: string;
    bankCode?: string;
  }): Promise<DeliverabilityResult>;

  /** 风险名单筛查(涉诈、司法、制裁) */
  screenPayee(input: { payeeName: string; accountNo?: string; phone?: string }): Promise<ScreeningResult>;

  /** 转账草稿(零副作用) */
  createTransferDraft(input: TransferIntent): Promise<TransferDraft>;
  /** 提交转账。执行器内部注入受限服务身份 */
  submitTransfer(input: { draftId: string; frozenPayloadHash: string; actionToken: string }): Promise<TransferReceipt>;

  /** 定时/周期任务 */
  createSchedule(input: ScheduleIntent): Promise<Schedule>;
  listSchedules(customerId: string): Promise<Schedule[]>;
  cancelSchedule(customerId: string, scheduleId: string): Promise<void>;

  /**
   * AA 收款。
   *
   * ★ 归属是**调用方身份**,不是"意向"的一部分:所以 customerId 是显式入参,
   *   与 cancelTransfer / listSchedules 等所有按客户隔离的操作保持一致。
   *   早期 createCollection 不记归属、listCollections 也不按归属过滤 ——
   *   于是任何客户都能读到**所有人**的 AA 账单(参与人姓名、手机号、金额)。
   */
  createCollection(customerId: string, input: CollectionIntent): Promise<Collection>;
  listCollections(customerId: string): Promise<Collection[]>;

  /** 撤销:仅在未清算窗口内可用 */
  cancelTransfer(customerId: string, transferId: string): Promise<CancelResult>;

  /** 幂等查询:按幂等键查是否已执行过 */
  findByIdempotencyKey(key: string): Promise<{ found: boolean; receipt?: TransferReceipt }>;

  /**
   * ★ 幂等登记:提交成功后把「这笔请求已经执行过」记下来。
   *
   * 为什么必须有写口:`findByIdempotencyKey` 是唯一的读点,但如果没人写,
   * 那条"重放不得产生第二笔转账"的分支就永远不可达 —— 只读不写等于没有幂等。
   */
  rememberIdempotency(key: string, receipt: TransferReceipt): Promise<void>;

  // ---- 两阶段提交(第 3 项:先定义提交点,再谈取消) ----
  //
  // ★ 为什么必须把提交点放进**银行核心接口**,而不是在执行器里加个 AbortSignal:
  //   资金操作的"取消"只有在**提交点之前**才可能是干净的。执行器并不知道
  //   钱是什么时候真正动了的 —— 只有银行核心知道。接口不说清提交点,
  //   执行器就只能猜,而猜错的代价是"钱扣了、状态未知"。
  //
  //   · prepareOperation:零副作用。只做校验与登记(冻结视图、幂等键占用),
  //     返回一个 preparedId。**它不动余额、不写业务状态。**
  //   · commitOperation:**唯一的副作用点**。它读取消信号:
  //       - 信号要求取消且本笔尚未提交 → 干净中止(余额不变);
  //       - 已经提交过(同 preparedId 重放)→ 幂等返回原回执,不再动账;
  //       - 提交之后才来的取消 → **不在这一层处理**,由编排器的补偿链
  //         (compensateWith)负责。这正是"不允许存在第三种状态"的落点:
  //         要么没提交(余额不变),要么提交了并留下补偿记录。
  //   · abortOperation:提交前撤销 prepare(零副作用),用于审计留痕。

  /**
   * 两阶段提交的第一阶段:准备(零副作用)。
   *
   * 返回 `{ ok: false, error }` 表示这一步**根本不可能提交**
   * (账户不存在、金额非法、幂等键已被占用……)——
   * 这种情况不该走到提交边界,更不该写一条"已取消"。
   */
  prepareOperation(req: {
    /** 银行核心操作名,如 "transfer.submit"(审计与排查用,必须稳定) */
    op: string;
    customerId: string;
    input: Record<string, unknown>;
    /** 请求级幂等键:同一键只可能有一笔真正提交 */
    idempotencyKey?: string;
    now?: number;
  }): Promise<PreparedOperation | { ok: false; error: string }>;

  /**
   * 两阶段提交的第二阶段:提交(**唯一副作用点**)。
   *
   * `signal` 就是 `ExecutionContext.cancellation` 的语义:
   * 只在 commit 之前有效 —— 一旦本笔已提交,再传 signal 也回不去。
   */
  commitOperation(
    preparedId: string,
    signal?: { requested: boolean; reason?: string; source?: string },
  ): Promise<CommitOutcome>;

  /** 提交前撤销(零副作用);若已提交则如实回报 `alreadyCommitted: true` */
  abortOperation(preparedId: string, reason: string): Promise<AbortOutcome>;

  /** 当前挂起(已 prepare 未 commit)的操作 —— 给审计与自检用 */
  listPreparedOperations(customerId?: string): Promise<PreparedOperation[]>;

  /**
   * 开启一段"执行作用域":提交边界会读这里的取消信号。
   *
   * ★ 为什么取消信号要**装在作用域上**,而不是绑在某个 AbortSignal 上:
   *   编排器在调用能力之前知道"用户已经要求取消",能力内部知道"我正要做哪笔
   *   银行操作",而**只有银行核心知道提交点在哪**。三者必须有一个交汇点,
   *   交汇点就是它:编排器设置一次,银行核心在 prepare 与 commit 之间读一次。
   *   信号是"读一次的数据",不是"随时能杀死执行的钩子" ——
   *   所以 commit 之后它一点作用都没有,回到已有的补偿链路。
   */
  beginOperationScope(scope: OperationScope): void;

  /** 结束执行作用域(必须在 finally 里调用,避免信号泄漏到下一笔操作) */
  endOperationScope(): void;

  // ---- 理财(场景三) ----
  //
  // ★ 为什么理财走 BankPort 而不是在能力层硬编码:
  //   产品目录、风险测评结果、持仓份额都是**银行侧的事实**,
  //   它们必须来自核心系统,不能被模型或能力层编造(I3)。
  //   理财的一切数字(净值、份额、收益、费率、到账时间)只有这一个可信来源。

  /** 产品目录查询。关键词/等级过滤在银行侧完成,支持按收益率排序。 */
  listWealthProducts(query: WealthProductQuery): Promise<WealthProduct[]>;
  /** 单个产品详情(含费率、赎回到账时效、风险提示原文) */
  getWealthProduct(productCode: string): Promise<WealthProduct | null>;
  /** 客户的理财持仓(含市值与累计收益) */
  listWealthHoldings(customerId: string): Promise<WealthHolding[]>;
  /** 活期挂牌利率。续接方案里的「不续投」对照只用这个数,不得改写成预计收益 */
  getDemandDepositRate(customerId: string): Promise<DemandDepositRate>;
  /** 记下续接选择。同一持仓只保留最新一条;不冻结资金、不创建申购 */
  saveRolloverChoice(input: {
    customerId: string;
    planId: string;
    holdingId: string;
    decision: WealthRolloverChoice["decision"];
    productCode: string | null;
    productName: string | null;
    amountBasis: number;
    status: WealthRolloverChoice["status"];
    gate: string;
    note: string;
  }): Promise<WealthRolloverChoice>;
  /** 该持仓上最新的续接选择;没有则 null */
  getRolloverChoice(customerId: string, holdingId: string): Promise<WealthRolloverChoice | null>;
  /** 客户的风险测评状态 */
  getRiskProfile(customerId: string): Promise<WealthRiskProfile>;
  /** 提交风险测评结果(问卷打分在能力层完成,此处只落库) */
  saveRiskProfile(
    customerId: string,
    input: { level: RiskLevel; score: number; validUntil: number; answers: Array<{ questionId: string; optionId: string }> },
  ): Promise<WealthRiskProfile>;
  /** 申购理财产品(冻结资金 → 确认份额) */
  submitWealthPurchase(input: WealthPurchaseInput): Promise<WealthPurchaseReceipt>;
  /** 赎回理财产品(减少份额 → T+N 到账) */
  submitWealthRedemption(input: WealthRedemptionInput): Promise<WealthRedemptionReceipt>;

  // ---- 卡片管理(场景四) ----
  //
  // ★ 卡片与账户是**两个不同的东西**,不能混在一个接口里:
  //   `listAccounts` 返回的是"钱在哪个账户",而客户口中的"我那张卡"
  //   问的是卡片本身 —— 卡号、有效期、卡状态(正常/挂失/冻结/未激活)、
  //   额度、交易限制、补卡进度。一张卡挂失后,它背后的账户仍然存在且能用,
  //   所以"卡状态"与"账户状态"必须能分别表达,否则系统会在客户说
  //   "卡丢了"时回答"你的账户一切正常" —— 答非所问,而且掩盖了紧急状态。
  //
  // ★ 这些接口里没有任何一个是"改手机号""改密码":那类操作在本项目里
  //   由能力层直接标记为 blocked 并引导原生流程,银行核心侧根本不提供代理入口。

  /** 客户名下全部卡片(含状态、额度、有效期与限制信息) */
  listCards(customerId: string): Promise<BankCard[]>;
  /** 单张卡详情 */
  getCard(customerId: string, cardId: string): Promise<BankCard | null>;
  /**
   * 提交额度调整申请。
   * ★ 语义是**提交申请**,不是"调整额度":银行核心只登记待审核工单,
   *   卡片额度在审核通过前不会变化。返回值里的 status 必须如实反映这一点。
   */
  submitLimitAdjustment(input: CardLimitAdjustmentInput): Promise<CardLimitAdjustmentReceipt>;
  /** 查询额度调整申请的当前状态(审核进度) */
  getLimitAdjustment(customerId: string, applicationId: string): Promise<CardLimitAdjustment | null>;
  /** 列出客户全部额度调整申请(最近的在前) */
  listLimitAdjustments(customerId: string, cardId?: string): Promise<CardLimitAdjustment[]>;
  /**
   * 挂失(冻结)卡片 —— **紧急安全动作**。
   * ★ 这是全系统唯一一个"先执行、后补充细节"的写操作:
   *   卡丢了的第一件事是让卡不能用,任何追问都会推迟止损。
   *   因此它不要求用户先补齐信息(补卡/换号等细节在冻结之后再聊)。
   */
  reportCardLoss(input: {
    customerId: string;
    cardId: string;
    reason?: string;
    /** 用户自述的丢失/被盗情形,用于风控留痕 */
    scenario?: string;
  }): Promise<CardLossReceipt>;
  /** 解除卡片交易限制的申请(需先查清原因;司法冻结类直接拒绝受理) */
  submitUnblockRequest(input: CardUnblockInput): Promise<CardUnblockReceipt>;
  /** 新卡申请(新开户 / 加办卡) */
  submitCardApplication(input: CardApplicationInput): Promise<CardApplication>;
  /** 挂失后补卡下单(换号 / 保留原号) */
  orderCardReplacement(input: CardReplacementInput): Promise<CardReplacementOrder>;
  /** 激活新卡(可选同时设置交易密码标志) */
  activateCard(input: {
    customerId: string;
    cardId: string;
    /** 是否在激活流程中设置交易密码 */
    setTransactionPassword: boolean;
    activationCode?: string;
  }): Promise<CardActivationReceipt>;

  // ---- 订阅代扣(新场景) ----
  //
  // ★ 为什么"识别"与"协议"必须分开取数:
  //   · 识别要从**流水**里认(客户自己也不会记得签过几份协议),
  //     所以走 fetchForAnalysis,由纯函数引擎判定关键词与固定周期金额;
  //   · "能不能在这里取消"只有**代扣协议**能回答,所以走 listSubscriptions。
  //   少了任何一个:要么认不出客户被扣的钱,要么会把"银行解不了的商户侧续费"
  //   说成"已帮你取消" —— 后者是过度承诺,比认不出更糟。

  /** 客户名下的代扣协议(含已被取消的历史协议,便于回答"我是不是已经关过了") */
  listSubscriptions(customerId: string): Promise<BankSubscription[]>;
  /** 单份代扣协议 */
  getSubscription(customerId: string, subscriptionId: string): Promise<BankSubscription | null>;
  /**
   * 取消代扣协议。
   * ★ 语义是**下一期起不再扣款**,不是"退款":本期已扣费用按 refundPolicy 处理。
   *   返回值里 nextDebitAtAfter 必须为 null —— 取消成功却还留着下次扣款日,
   *   那是把"申请"读成了"结果"的另一种形式。
   */
  cancelSubscription(input: SubscriptionCancelInput): Promise<SubscriptionCancelReceipt>;

  // ---- 跨场景事件联动(新场景) ----
  //
  // ★ 为什么"事件"与"方案"必须由银行侧事实驱动,而不是模型自由发挥:
  //   客户说「下个月15号有个重要纪念日帮我规划下」时,系统要回答的其实是
  //   一个**多来源的算术题**:那天前后有哪些固定扣款、账上还剩多少可动用、
  //   这笔准备要占掉多少、以及"下单"这件事谁来做。
  //   这四个数分别住在流水、代扣协议、账户与外部商户目录里 ——
  //   模型一个都编不出来(I3),所以必须从银行侧取。
  //
  // ★ 另一条更重要的分界:**这里没有任何"替客户下单""替客户锁钱"的接口**。
  //   reserveFunds / placeExternalOrder 都只登记**客户已确认的那一步**,
  //   且各自带独立的回执;方案生成阶段拿不到它们。

  /** 客户的关键事件(生日/纪念日/发薪日/大额支出预备窗口等) */
  listLifeEvents(customerId: string): Promise<LifeEvent[]>;
  /**
   * 登记一条客户**自述**的关键事件。
   * ★ 语义只是"记下来":它不改动任何资金状态,也不创建任何订单 ——
   *   所以它可以自动执行(与客户侧记账批注同一档),而不是黄色。
   */
  saveLifeEvent(input: LifeEventInput): Promise<LifeEvent>;
  /** 外部服务商户目录(鲜花/蛋糕/餐厅/酒店等——"外部订购"的候选来源) */
  listExternalMerchants(query: { category?: string; keyword?: string }): Promise<ExternalMerchant[]>;

  /**
   * 资金操作步骤:按客户确认的口径**预留**一笔资金、登记一个定时任务,或解开此前预留的资金。
   * ★ 语义是"预留/解除预留",不是"划走":钱仍在客户账户名下,
   *   只是"还能不能用"这件事变了 —— 而这正是必须让客户确认的原因。
   */
  applyFundStep(input: EventFundStepInput): Promise<EventFundStepReceipt>;
  /**
   * 查某一步当前有没有生效中的资金预留。
   * ★ 为什么需要这个只读口:客户说「把刚才那个预留解开」时,系统必须先知道
   *   **到底有没有这么一笔**。没有就去解开,等于凭空多出钱来;
   *   而"先执行、失败了再说"会让客户看到"办理失败",误以为是自己操作错了。
   */
  getEventFundTask(
    customerId: string,
    planId: string,
    stepId: string,
  ): Promise<{ active: boolean; mode: string; amount: number; fromAccountId: string } | null>;
  /**
   * 外部服务操作步骤:向**外部商户**下一笔单(模拟)。
   * ★ 这是全系统里最需要"强验证"的一类动作:钱离开银行体系、变成一份商户订单,
   *   且回退要跟商户协商。所以它单独成接口,且只在红色(strong_auth)档被调用。
   */
  placeExternalOrder(input: EventExternalStepInput): Promise<EventExternalStepReceipt>;

  /**
   * 客户名下已上传/已受理的材料(合同、报价单、发票、回单等)。
   *
   * ★ 只读。材料本身由客户在业务办理过程中提交,Agent 只能**读来判断是否自相矛盾**,
   *   不能改写、不能补录 —— 否则"比对"就没有意义了(比的是客户提交的原件)。
   */
  listDocuments(customerId: string): Promise<CustomerDocument[]>;
  getDocument(customerId: string, documentId: string): Promise<CustomerDocument | null>;
}

export interface Account {
  accountId: string;
  customerId: string;
  /** 脱敏卡号/账号,如 **** **** **** 1234 */
  maskedNo: string;
  type: "current" | "savings" | "credit" | "ewallet";
  currency: string;
  balance: number;
  availableBalance: number;
  /** 授信额度(信用卡/透支账户才有) */
  creditLimit?: number;
  status: "active" | "frozen" | "closed";
}

export interface TransactionQuery {
  accountId?: string;
  from?: number;
  to?: number;
  minAmount?: number;
  maxAmount?: number;
  counterparty?: string;
  category?: string;
  direction?: "in" | "out";
  limit?: number;
}

export interface Transaction {
  transactionId: string;
  accountId: string;
  direction: "in" | "out";
  amount: number;
  currency: string;
  counterpartyName: string;
  counterpartyId?: string;
  category?: string;
  /** 交易备注 —— 注意:这是**不可信输入**,是 prompt injection 的主要载体 */
  memo?: string;
  balanceAfter: number;
  ts: number;
  /**
   * ★ 这笔流水对应的转账回执编号(仅有转账类流水)。
   *
   * 为什么必须回填:回执表以 `transferId`(TRF_…)为键,而流水用 `transactionId`(TXN_…)。
   * 撤销入口是从"近期流水"里挑最近一笔转出,如果只拿得到 TXN_,银行侧就永远找不到那张回执
   * —— 实测中「撤销刚才那笔转账」因此必然失败,客户看到的是「操作未能完成:未知原因」。
   */
  transferId?: string;
  /** 客户可见的流水号(与回执上的 reference 一致,撤销卡要显示同一个号) */
  reference?: string;
}

export interface PayeeQuery {
  /** 姓名(支持模糊) */
  name?: string;
  /** 手机号(支持后四位) */
  phone?: string;
  /** 所属银行 */
  bankCode?: string;
  limit?: number;
}

export interface Payee {
  payeeId: string;
  name: string;
  /** 脱敏账号 */
  maskedAccountNo?: string;
  phone?: string;
  bankCode: string;
  bankName: string;
  /** 该收款人的"新颖度" —— 分级的关键输入 */
  novelty: {
    /** 是否为首次转账(历史上从未成功转过) */
    isFirstTime: boolean;
    /** 历史成功转账笔数 */
    successCount: number;
    /** 最近一次成功转账时间 */
    lastSuccessAt?: number;
  };
  /** 是否为同户名(本人名下账户互转,风险最低) */
  isSelfOwned: boolean;
  /** 是否在客户白名单 */
  isWhitelisted: boolean;
  /** 客户为该收款人设置的别名 */
  aliases?: string[];
}

export interface DeliverabilityResult {
  deliverable: boolean;
  /** 户名与账号是否完全匹配 */
  nameMatched: boolean;
  /** 实际户名(可能被部分掩码) */
  actualNameMasked?: string;
  /** 需要用户确认的相似度提示 */
  nameSimilarity?: number;
  bankName?: string;
  /** 跨行 / 跨境标志,影响费用与到账时间 */
  interbank: boolean;
  crossBorder: boolean;
  /** 预计到账时间描述 */
  estimatedArrival?: string;
  /**
   * 预计手续费。★ 与金额有关,所以**可达性查询(不知道金额)不许填这个字段** ——
   * 规则唯一出处:`capabilities/transferFee.ts`。把"没算过"填成 0,
   * 客户看到的就是"免手续费",而条款可能说的是要收费。
   */
  fee?: number;
}

export interface ScreeningResult {
  /** 是否命中名单 */
  hit: boolean;
  /** 命中类型 */
  hits: Array<{
    listType: "fraud" | "judicial" | "sanction" | "internal_blacklist" | "reported_account";
    severity: "block" | "warn";
    detail: string;
  }>;
}

/** 转账意图 —— 计划器与执行器之间的契约 */
export interface TransferIntent {
  fromAccountId: string;
  /** 解析后的收款人(可能为尚未确认的候选) */
  payee: { payeeId?: string; name: string; accountNo?: string; phone?: string; bankCode?: string };
  amount: number;
  currency: string;
  /** 备注。写入前必须经过净化(见 B5 备注净化) */
  memo?: string;
  /** 用途分类(可能触发合规校验) */
  purpose?: string;
  /** 计划执行时间(定时转账) */
  scheduledAt?: number;
  /** 是否为周期任务 */
  recurrence?: { frequency: "daily" | "weekly" | "monthly"; interval: number; until?: number };
}

export interface TransferDraft {
  draftId: string;
  intent: TransferIntent;
  /** 冻结载荷哈希 —— I4 */
  frozenPayloadHash: string;
  /** 载荷内容(用于生成人话确认卡) */
  frozenPayload: Record<string, unknown>;
  fee: number;
  estimatedArrival: string;
  createdAt: number;
  expiresAt: number;
  warnings: string[];
}

export interface TransferReceipt {
  transferId: string;
  status: "succeeded" | "pending" | "failed";
  amount: number;
  fee: number;
  currency: string;
  payeeName: string;
  executedAt: number;
  /** 可撤销截止时间(未清算窗口) */
  cancellableUntil?: number;
  /** 流水号(客户可凭此查询) */
  reference: string;
  /**
   * ★ 出账账户 —— 退款必须退到**这一笔自己的**出账账户。
   *
   * 为什么不能靠猜:早期实现按「对手方名 + 金额」在整个世界里找一条流水来入账,
   * 同额同收款人的旧流水会被误选(钱退到错误的账户),找不到时还会照样回 ok:true
   * ——回执说退了、账上没退。把出账账户冻结在回执上,退款就不再依赖任何匹配。
   */
  fromAccountId: string;
  /** ★ 对应的交易流水号(TXN_…):撤销入口从流水侧过来,需要靠它回到这张回执 */
  transactionId: string;
}

export interface ScheduleIntent {
  transferIntent: TransferIntent;
  /** 首次执行时间 */
  firstRunAt: number;
  recurrence: { frequency: "once" | "daily" | "weekly" | "monthly"; interval: number; until?: number };
  /** 余额不足时的策略 */
  onInsufficientFunds: "notify_and_skip" | "retry_next_day" | "partial";
  /** 执行前是否提醒(反诈关键:给用户一个反悔窗口) */
  preExecutionReminder: boolean;
}

export interface Schedule {
  scheduleId: string;
  status: "active" | "paused" | "completed" | "cancelled";
  nextRunAt: number;
  intent: TransferIntent;
  recurrence: ScheduleIntent["recurrence"];
  createdAt: number;
}

/** AA 收款 —— 由发起人创建一笔待分摊账单 */
export interface CollectionIntent {
  title: string;
  totalAmount: number;
  currency: string;
  /** 分摊方式 */
  splitMode: "equal" | "custom" | "shares";
  /** 参与人(自然人维度,不要求已是收款人) */
  participants: Array<{
    displayName: string;
    phone?: string;
    payeeId?: string;
    /** custom 模式下的金额;shares 模式下的份数 */
    amount?: number;
    shares?: number;
  }>;
  /** 谁承担手续费 */
  feeBearer: "initiator" | "each";
  /** 截止时间 */
  deadline?: number;
  /** 是否允许部分支付 */
  allowPartial: boolean;
}

export interface Collection {
  collectionId: string;
  /** ★ 发起人:AA 账单必须按归属隔离,否则另一个客户会读到参与人姓名/手机号/金额 */
  customerId: string;
  title: string;
  totalAmount: number;
  currency: string;
  status: "open" | "partially_paid" | "completed" | "expired" | "cancelled";
  shares: Array<{
    participantName: string;
    participantId?: string;
    amountDue: number;
    amountPaid: number;
    status: "pending" | "paid" | "expired" | "declined";
    /** 单人收款链接(用于分享,注意不要泄露他人金额) */
    paymentLink?: string;
  }>;
  createdAt: number;
}

export interface CancelResult {
  ok: boolean;
  reason?: string;
  refundAmount?: number;
}

// ============================================================================
// 五之二、理财(场景三)—— 产品、持仓、风险测评
// ============================================================================

/**
 * 客户风险承受能力等级(由风险测评问卷得出)。
 *
 * ★ 这是**监管口径**的等级,与产品的 R1–R5 是同一把尺子 ——
 *   正因为同一把尺子,才能做"只能买不超过自己等级的产品"这个判断。
 *   尺子不一致,"匹配"二字就没有意义。
 */
export type RiskLevel = "C1" | "C2" | "C3" | "C4" | "C5";

/** 产品风险等级。数字部分与客户等级一一对应:R3 对应 C3。 */
export type ProductRiskLevel = "R1" | "R2" | "R3" | "R4" | "R5";

/** 产品大类 */
export type WealthProductType =
  /** 现金管理类(货币基金 / 活期理财)—— T+0 */
  | "cash"
  /** 固定收益类(债券型)—— T+1 */
  | "fixed_income"
  /** 混合类 —— T+1/T+2 */
  | "mixed"
  /** 权益类(股票型 / 指数型)—— T+2 */
  | "equity"
  /** 大额存单 / 定期存款类 —— 到期自动回款 */
  | "deposit";

/** 赎回到账时效 —— ★ 必须逐产品明确告知用户 */
export type SettlementCycle =
  /** 当日到账 */
  | "T+0"
  /** 次一工作日到账 */
  | "T+1"
  /** 第二工作日到账 */
  | "T+2";

/**
 * 理财产品快照。
 *
 * ★ 关于收益率的口径:这里只提供**历史业绩**与**业绩比较基准**,
 *   不存在任何"预期收益""保证收益"字段 —— 这是刻意的结构设计。
 *   字段层面就不给"保本保收益"留位置,话术层面才可能不出现它。
 */
export interface WealthProduct {
  productCode: string;
  name: string;
  /** 产品大类 */
  type: WealthProductType;
  riskLevel: ProductRiskLevel;
  /** 起购金额 */
  minAmount: number;
  /** 递增单位(追加金额需为它的整数倍) */
  incrementAmount: number;
  /** 产品期限(天)。null 表示无固定期限,可随时赎回 */
  termDays: number | null;
  /** 近 7 日年化(%)。货币/现金类口径 */
  yield7d: number | null;
  /** 近 1 年年化(%)。净值型产品口径 */
  yield1y: number | null;
  /** 业绩比较基准(%) —— ★ 不是承诺收益,展示时必须原样带出这个措辞 */
  performanceBenchmark: number | null;
  /** 单位净值 */
  nav: number;
  /** 净值日期 */
  navDate: number;
  /** 管理费率(%/年) */
  managementFeeRate: number;
  /** 托管费率(%/年) */
  custodyFeeRate: number;
  /** 申购费率(%) */
  purchaseFeeRate: number;
  /** 赎回到账时效 */
  settlement: SettlementCycle;
  /** 是否支持随时赎回 */
  redeemable: boolean;
  /** 最短持有天数(0 表示无限制) */
  minHoldingDays: number;
  /** 销售状态 */
  status: "on_sale" | "suspended" | "sold_out" | "closed";
  /**
   * 风险提示原文。★ 每条展示路径都必须带出它 ——
   * 不是"可选文案",而是产品数据的一部分。
   */
  riskDisclosure: string;
  /** 一句话产品特征(用于推荐时的客观描述) */
  highlight: string;
  /**
   * 近 6 个月最大回撤。
   *
   * ★ 没有这个字段就当「未披露」,调用方不得用 highlight 里的散文补一个数。
   *   窗口、算法、截止日必须一起出现,否则一个百分比没有可比性。
   */
  maxDrawdown6m?: MaxDrawdown6m | null;
}

/** 近 6 个月最大回撤(银行侧事实,不是模型估算) */
export interface MaxDrawdown6m {
  /** 回撤幅度,百分比点数。1.2 表示 1.20%,不是「最多只会亏 1.2%」 */
  pct: number;
  windowStart: number;
  windowEnd: number;
  /** 计算方法原文,例如「区间内复权净值从峰值到谷值的最大跌幅」 */
  method: string;
  asOf: number;
}

/** 到期后资金怎么走。必须来自持仓,不能默认成「掉进活期」 */
export type MaturityDisposition = "to_demand" | "auto_rollover" | "customer_instruction";

/** 人民币活期存款挂牌利率。和理财业绩分列,禁止合成「预计年化」 */
export interface DemandDepositRate {
  /** 年化百分数。0.2 表示 0.20% */
  annualRatePct: number;
  effectiveFrom: number;
  accountTypeLabel: string;
  asOf: number;
  source: string;
}

/**
 * 客户对一笔到期续接的选择。
 *
 * ★ 这不是申购。status 不会是 purchased。
 *   资金仍在份额里时只能是 awaiting_credit;到账之后仍要再走申购确认。
 */
export interface WealthRolloverChoice {
  choiceId: string;
  customerId: string;
  planId: string;
  holdingId: string;
  decision: "renew" | "stay_demand";
  productCode: string | null;
  productName: string | null;
  /** 金额口径:生成方案时的市值,不是已冻结金额 */
  amountBasis: number;
  status: "awaiting_credit" | "ready_to_confirm" | "declined";
  /** 资金闸门代码,便于审计检索为什么没有申购 */
  gate: string;
  createdAt: number;
  note: string;
}

export interface WealthProductQuery {
  /** 关键词(产品名/类型/等级,如"稳健""债券""货币") */
  keyword?: string;
  /** 只看某个风险等级及以下 */
  maxRiskLevel?: ProductRiskLevel;
  /** 产品大类过滤 */
  type?: WealthProductType;
  /** 排序维度 */
  sortBy?: "yield" | "risk" | "term" | "minAmount";
  /** 只看起购金额不超过该值的产品 */
  maxMinAmount?: number;
  limit?: number;
}

/** 理财产品持仓 */
export interface WealthHolding {
  holdingId: string;
  productCode: string;
  productName: string;
  type: WealthProductType;
  riskLevel: ProductRiskLevel;
  /** 持有份额 */
  shares: number;
  /** 累计投入本金 */
  costAmount: number;
  /** 单位成本净值 */
  avgCostNav: number;
  /** 当前单位净值 */
  nav: number;
  /** 当前市值 */
  marketValue: number;
  /** 累计收益(市值 − 本金) */
  profit: number;
  /** 累计收益率(%) */
  profitRate: number;
  /** 首次申购时间 */
  firstPurchaseAt: number;
  /** 赎回到账时效 */
  settlement: SettlementCycle;
  /** 持有天数 */
  holdingDays: number;
  /**
   * 银行侧到期日。
   *
   * ★ 有固定期限的产品才有。不要用「首次申购日 + 期限」在调用方现算:
   *   中途买入、提前到期、自动续期都会让那个加法说错日子。
   *   没有这个字段,就不要给这笔持仓出续接方案。
   */
  maturityAt?: number | null;
  /** 到期后的处置。缺省表示银行没给,方案里必须明说不知道 */
  maturityDisposition?: MaturityDisposition | null;
  /**
   * 银行是否已经把到期资金记入活期。
   * 只有这个标记为真,才允许进入申购确认。份额还在、或标记未到,都不能买。
   */
  maturityCredited?: boolean;
}

/** 客户风险承受能力测评状态 */
export interface WealthRiskProfile {
  customerId: string;
  /** 是否已完成过测评 */
  assessed: boolean;
  /** 测评得出的等级 */
  level: RiskLevel | null;
  /** 问卷得分 */
  score: number | null;
  /** 测评时间 */
  assessedAt: number | null;
  /** 有效期截止(监管惯例:一年一评) */
  validUntil: number | null;
  /** 是否已过期 */
  expired: boolean;
  /** 等级对应的可买产品上限(R 等级) */
  maxProductRiskLevel: ProductRiskLevel | null;
  /** 等级描述 */
  levelLabel: string;
}

export interface WealthPurchaseInput {
  customerId: string;
  productCode: string;
  /** 申购金额 */
  amount: number;
  fromAccountId: string;
  /** 冻结载荷哈希(I4) */
  frozenPayloadHash: string;
  /**
   * ★ 风险不匹配确认书的签署凭据。
   *   仅在"客户等级 < 产品等级"时需要;它是**用户显式确认过**的事实记录,
   *   不是模型可以填空的字段 —— 由编排器在用户点击确认后写入。
   */
  consentRef?: string;
}

export interface WealthPurchaseReceipt {
  orderId: string;
  status: "confirmed" | "frozen" | "failed";
  productCode: string;
  productName: string;
  amount: number;
  /** 申购确认净值 */
  confirmedNav: number;
  /** 确认份额 */
  shares: number;
  /** 申购费 */
  fee: number;
  /** 资金冻结金额(承诺类:不动钱,但资金被冻结) */
  frozenAmount: number;
  confirmedAt: number;
  /** 份额确认预计时间 */
  sharesConfirmedAt: number;
  /** 风险不匹配确认书编号(如适用) */
  consentRef?: string;
  reference: string;
}

export interface WealthRedemptionInput {
  customerId: string;
  holdingId: string;
  /** 赎回份额(与 amount 二选一) */
  shares?: number;
  /** 赎回金额(按当前净值折算份额) */
  amount?: number;
  frozenPayloadHash: string;
}

export interface WealthRedemptionReceipt {
  orderId: string;
  status: "accepted" | "failed";
  productCode: string;
  productName: string;
  /** 赎回份额 */
  shares: number;
  /** 按申请日净值估算的金额 */
  estimatedAmount: number;
  /** 赎回费 */
  fee: number;
  /** 到账时效 */
  settlement: SettlementCycle;
  /** 预计到账时间 */
  estimatedArrivalAt: number;
  /** ★ 收益影响提示:本次赎回兑现的收益(可为负) */
  realizedProfit: number;
  /** 剩余份额 */
  remainingShares: number;
  submittedAt: number;
  reference: string;
}

// ============================================================================
// 五之三、卡片管理(场景四)—— 卡片、额度、限制、挂失补卡与激活
// ============================================================================

/**
 * 卡片形态。
 *
 * ★ 区分"信用卡"与"借记卡"不是为了排版好看,而是因为下面两件事只有信用卡才有:
 *   ① 额度(借记卡没有授信额度,客户说"额度太低"必然是在说信用卡);
 *   ② 交易限制的常见成因(异常交易、余额不足以外的风控)。
 *   系统必须先知道客户问的是哪一类,才不会对一个借记卡客户解释"提额审核"。
 */
export type CardKind =
  /** 信用卡(有授信额度) */
  | "credit"
  /** 借记卡 / 储蓄卡 */
  | "debit"
  /** 虚拟卡(仅线上支付) */
  | "virtual";

/**
 * 卡片状态。
 *
 * ★ 这里刻意把"挂失"与"冻结"分成两个不同的状态:
 *   挂失是**客户主动**发起的(卡丢了),冻结是**银行/司法**施加的。
 *   两者对客户的下一步动作完全不同 ——
 *   挂失之后要做的是补卡;冻结之后要做的是查清原因、按原因去解决。
 *   合并成一个"异常"状态,系统就无法回答"我该做什么"。
 */
export type CardStatus =
  /** 正常可用 */
  | "active"
  /** 客户主动挂失(可补卡) */
  | "lost"
  /** 银行/司法侧冻结(需查原因) */
  | "frozen"
  /** 新卡未激活(不能用) */
  | "pending_activation"
  /** 已补卡发出的新卡在途 */
  | "replacement_in_transit"
  /** 已销卡 */
  | "closed"
  /** 已过期 */
  | "expired";

/** 交易限制的原因分类 —— ★ 行业规则要求"不能一刀切,必须先查清原因" */
export type RestrictionCause =
  /** 异常交易(疑似盗刷/套现) */
  | "abnormal_transaction"
  /** 身份信息不完整 / 证件过期 */
  | "incomplete_information"
  /** 司法冻结(法院/公安等有权机关) */
  | "judicial_freeze"
  /** 安全风险(疑似账户接管、密码泄露、设备异常) */
  | "security_risk"
  /** 客户自己设置的限额/开关 */
  | "self_setting";

/** 限制的处理通道 —— 决定"我们能不能帮你办" */
export type RestrictionChannel =
  /** Agent 可受理解除申请(转银行审核) */
  | "agent_application"
  /** 必须由客户在原生安全流程中自助完成(如补充证件信息) */
  | "native_self_service"
  /** 只能凭有权机关的解除文书办理,Agent 与银行都不能自行解除 */
  | "authority_document_only";

/** 卡片交易限制的详细情况 */
export interface CardRestriction {
  cause: RestrictionCause;
  causeLabel: string;
  /** 面向客户的说明(讲清"为什么被限制") */
  detail: string;
  /** 处理通道 */
  channel: RestrictionChannel;
  /** 客户需要准备的材料 */
  requiredDocuments: string[];
  /** 预计处理时效(人话) */
  estimatedResolution: string;
  /** 发生时间 */
  since: number;
  /** ★ 是否属于"必须先查清原因"的情形:全部限制都是,保留字段是为了未来放宽 */
  mustInvestigateFirst: boolean;
}

/** 卡片信息(银行侧事实) */
export interface BankCard {
  cardId: string;
  customerId: string;
  /** 产品名,如「长城环球通白金卡」 */
  productName: string;
  kind: CardKind;
  kindLabel: string;
  /** 卡组织 */
  brand: "unionpay" | "visa" | "mastercard";
  brandLabel: string;
  /** 脱敏卡号,如 **** **** **** 1234 */
  maskedNo: string;
  /** 卡号后四位(用户最常用来指认一张卡) */
  last4: string;
  status: CardStatus;
  statusLabel: string;
  /** 授信额度(仅信用卡;借记卡为 null) */
  creditLimit: number | null;
  /** 已用额度 */
  usedAmount: number | null;
  /** 可用额度 */
  availableLimit: number | null;
  /** 取现额度 */
  cashLimit: number | null;
  currency: string;
  /** 账单日 */
  statementDay: number | null;
  /** 还款日 */
  dueDay: number | null;
  /** 有效期(时间戳) */
  expiresAt: number;
  /** 开卡日期(用于判断"用卡满 6 个月"这条提额前置) */
  openedAt: number;
  /** 最近一次额度调整时间(用于冷却期判定) */
  lastLimitAdjustmentAt: number | null;
  /** 最近一次额度调整幅度 */
  lastLimitAdjustmentDelta: number | null;
  /** 交易限制(正常时为 null) */
  restriction: CardRestriction | null;
  /** 是否为挂失后补发的新卡 */
  replacementOf: string | null;
  /** 挂失时间 */
  lostAt: number | null;
  /** 是否已激活(新卡到手的必答问题) */
  activated: boolean;
  activatedAt: number | null;
  /** 是否已设置交易密码 —— 决定"激活之后还要不要设密码" */
  transactionPasswordSet: boolean;
  /** 关联的账户 ID(用于说明"卡冻结但账户仍在") */
  linkedAccountId: string | null;
}

/** 额度调整申请的当前环节 */
export interface CardLimitAdjustment {
  applicationId: string;
  cardId: string;
  cardLast4: string;
  /** 申请的额度(目标额度) */
  requestedLimit: number;
  /** 申请前的额度 */
  currentLimit: number;
  status: "submitted" | "under_review" | "approved" | "rejected" | "cancelled";
  statusLabel: string;
  submittedAt: number;
  /** 预计出结果时间 */
  estimatedDecisionAt: number;
  /** 审核意见(拒绝时给原因) */
  decisionNote?: string;
  /** 是否为提额(降额属于安全方向,流程不同) */
  direction: "increase" | "decrease";
}

export interface CardLimitAdjustmentInput {
  customerId: string;
  cardId: string;
  /** 目标额度 */
  requestedLimit: number;
  /** 客户自述用途(如"装修""出差")—— 供审核参考 */
  purpose?: string;
  frozenPayloadHash: string;
}

export interface CardLimitAdjustmentReceipt {
  applicationId: string;
  cardId: string;
  cardLast4: string;
  requestedLimit: number;
  currentLimit: number;
  /** ★ 提交后一定是"审核中",绝不会是"已提额" */
  status: "submitted" | "under_review";
  statusLabel: string;
  submittedAt: number;
  estimatedDecisionAt: number;
  /** 面向客户的口径说明(我们帮你做 vs 银行审核说了算) */
  wording: string;
  reference: string;
}

export interface CardLossReceipt {
  cardId: string;
  cardLast4: string;
  ok: boolean;
  /** 冻结完成时间 —— 挂失的核心动作 */
  frozenAt: number;
  /** 是否即时生效 */
  immediate: boolean;
  reference: string;
  /** 冻结后客户仍需要知道的事(补卡选择等) */
  nextSteps: string[];
}

export interface CardUnblockInput {
  customerId: string;
  cardId: string;
  /** 客户自述情况 */
  statement?: string;
  frozenPayloadHash: string;
}

export interface CardUnblockReceipt {
  ok: boolean;
  accepted: boolean;
  cardId: string;
  applicationId: string;
  cause: RestrictionCause;
  channel: RestrictionChannel;
  /** 受理或拒绝受理的说明 */
  message: string;
  estimatedResolution: string;
  reference: string;
}

export interface CardApplicationInput {
  customerId: string;
  /** 申请卡种 */
  kind: CardKind;
  /** 期望的额度(仅信用卡) */
  requestedLimit?: number;
  /** 客户自述用途 */
  purpose?: string;
  frozenPayloadHash: string;
}

export interface CardApplication {
  applicationId: string;
  kind: CardKind;
  kindLabel: string;
  status: "submitted" | "under_review" | "approved" | "rejected";
  statusLabel: string;
  requestedLimit: number | null;
  submittedAt: number;
  estimatedDecisionAt: number;
  /** 需要客户补充的材料 */
  requiredDocuments: string[];
  /** 新卡到手后的必做动作 —— ★ 必须提前告知"还要激活" */
  postApprovalSteps: string[];
  reference: string;
}

export interface CardReplacementInput {
  customerId: string;
  cardId: string;
  /** 换号 / 保留原号 */
  mode: "new_number" | "keep_number";
  frozenPayloadHash: string;
}

export interface CardReplacementOrder {
  orderId: string;
  cardId: string;
  cardLast4: string;
  mode: "new_number" | "keep_number";
  modeLabel: string;
  status: "accepted" | "failed";
  /** 新卡预计到手时间 */
  estimatedArrivalAt: number;
  /** 预计到手天数(工作日)—— ★ 换号约 5 天、保留原号约 12 天,这个差异必须在操作前告知 */
  estimatedDays: number;
  /** ★ 新卡到手后要不要激活、要不要重设交易密码 —— 必须在操作前告知 */
  requiresActivation: boolean;
  requiresTransactionPassword: boolean;
  /** 卡号是否变化 */
  cardNumberChanges: boolean;
  newCardLast4: string | null;
  submittedAt: number;
  reference: string;
  /** 面向客户的差异说明 */
  wording: string;
}

export interface CardActivationReceipt {
  cardId: string;
  cardLast4: string;
  ok: boolean;
  activatedAt: number;
  /** 本次是否设置了交易密码 */
  transactionPasswordSet: boolean;
  /** 交易密码是否沿用原密码(换卡补卡沿用,新开户需新设) */
  transactionPasswordInherited: boolean;
  message: string;
  reference: string;
}

// ============================================================================
// 订阅代扣(新场景)
// ============================================================================

/** 代扣周期。与账单分析的 cadence 同口径,但这里只保留"可签约"的三种 */
export type SubscriptionCadence = "monthly" | "weekly" | "yearly";

/**
 * 取消的生效口径。
 *
 * ★ 这是本场景最容易骗人的一个字段:
 *   客户说"把会员关了",心里想的是"钱退回来"。而绝大多数代扣协议的语义是
 *   **"下一期不再扣"**,本期已经扣掉的费用不退(权益已经使用了)。
 *   把这两件事混起来,客户会在下个月发现钱还是少了,或者以为钱会退回来。
 */
export type SubscriptionCancelEffective = "next_cycle" | "immediate";

/** 签约渠道 / 解约通道 */
export type SubscriptionChannel =
  /** 银行侧代扣协议:本行可在对话内受理解约 */
  | "bank_mandate"
  /** 商户侧自动续费(第三方/卡组织代扣):银行侧没有协议可解,只能去商户侧关 */
  | "merchant_side";

/**
 * 一笔订阅代扣的**银行侧事实**(代扣协议)。
 *
 * ★ 与"从流水识别出来的候选"严格区分:
 *   流水只能证明"这个月被扣了 19 元",它证明不了"有没有一份可以在这里解的协议"。
 *   代扣协议是银行核心的事实,只有它能回答"能不能在这里一键取消"。
 *   两者交叉核对之后,才会有三种结论:可解约 / 只能商户侧关 / 已取消。
 */
export interface BankSubscription {
  subscriptionId: string;
  customerId: string;
  /** 商户名(与流水的 counterpartyName 对齐,便于交叉核对) */
  merchantName: string;
  /** 每期扣费金额 */
  amount: number;
  currency: string;
  cadence: SubscriptionCadence;
  cadenceLabel: string;
  /** 下次扣款时间(取消后为 null) */
  nextDebitAt: number | null;
  /** 协议状态 */
  status: "active" | "cancelled";
  statusLabel: string;
  /** 签约渠道:决定"能不能在这里取消" */
  channel: SubscriptionChannel;
  channelLabel: string;
  /** 签约时间 */
  signedAt: number;
  /** 取消时间(已取消时) */
  cancelledAt: number | null;
  /** 取消的生效口径 */
  cancelEffective: SubscriptionCancelEffective;
  /** 已经扣掉的费用怎么处理 —— 必须原样讲给客户 */
  refundPolicy: string;
  /** 取消的后果(权益终止 / 保障中断 / 需重新签约等) */
  cancelConsequence: string;
  /** 若只能商户侧关闭:那一侧的操作路径 */
  merchantCancelPath: string | null;
  category: string;
  /** 协议编号(对客户展示用的短号) */
  agreementNo: string;
}

export interface SubscriptionCancelInput {
  customerId: string;
  subscriptionId: string;
  /** 客户自述的取消原因,供留存 */
  reason?: string;
  /** 主体审核结果(与确认卡一一对应) */
  frozenPayloadHash?: string;
}

export interface SubscriptionCancelReceipt {
  ok: boolean;
  subscriptionId: string;
  merchantName: string;
  status: "cancelled";
  statusLabel: string;
  cancelledAt: number;
  /** 生效口径:next_cycle = 下一期起不再扣款 */
  effective: SubscriptionCancelEffective;
  /** 取消后的下次扣款时间(取消成功则必然为 null) */
  nextDebitAtAfter: number | null;
  refundPolicy: string;
  cancelConsequence: string;
  wording: string;
  reference: string;
}

// ============================================================================
// 跨场景事件联动(新场景)
// ============================================================================

/**
 * 关键事件的种类。
 *
 * ★ 这里刻意**只放"能被数据或客户明确说出来"的几类**:
 *   · birthday / anniversary —— 客户自述(或日程)给出;
 *   · payday               —— 由流水的规律性入账**推断**出来(不是客户说的);
 *   · big_expense          —— 由账单侧的大额支出与固定扣款**推断**出来;
 *   · travel               —— 客户自述;
 * 一旦种类无限扩张,触发器就会变成"模型自由发挥"的地方 ——
 * 而这个场景的全部价值恰好在于:方案里每一个数字都有出处。
 */
export type EventKind = "birthday" | "anniversary" | "payday" | "big_expense" | "travel" | "renewal_window";

/** 事件是怎么被识别出来的 —— 决定它在方案里能说多硬的话 */
export type EventSource = "user_stated" | "calendar" | "bills";

export interface LifeEvent {
  eventId: string;
  customerId: string;
  kind: EventKind;
  kindLabel: string;
  /** 面向客户的事件名,如「结婚纪念日」 */
  title: string;
  /** 事件发生时间 */
  occursAt: number;
  /** 提前多少天进入"规划窗口" */
  leadDays: number;
  /** 客户自述的补充信息(如"她喜欢百合") */
  note?: string;
  source: EventSource;
  sourceLabel: string;
  /** 预算上限(客户自述时有;没有则由方案侧按可动用余额给出建议区间) */
  budgetHint?: number;
}

export interface LifeEventInput {
  customerId: string;
  kind: EventKind;
  title: string;
  occursAt: number;
  leadDays?: number;
  note?: string;
  budgetHint?: number;
  /** 客户原话,供留存 */
  rawText?: string;
}

/** 外部服务商户(鲜花/蛋糕/餐厅/酒店 —— "外部订购"的候选来源) */
export interface ExternalMerchant {
  merchantId: string;
  name: string;
  category: string;
  categoryLabel: string;
  /** 起送/起订金额 */
  minAmount: number;
  /** 商户主推的单品(方案里"要约什么"必须有具体名目,不能是"订一个东西") */
  hotItem: string;
  /** 提前几天预约 */
  bookAheadDays: number;
  /** 能不能当天送达 */
  sameDayDelivery: boolean;
  /** 取消政策 —— ★ 必须能讲给客户(退订的代价) */
  cancelPolicy: string;
  rating: number;
}

/**
 * 方案里的一步。
 *
 * ★ 这是整个场景的核心结构,它只回答三个问题:
 *   这一步属于「资金操作」还是「外部服务操作」?它现在能做吗(分级)?
 *   以及 —— **钱从哪出、给谁、多少、什么时候。**
 *
 *   `funds` 字段不是可选的美化信息:**只要一步会动到钱或产生外部订单,
 *   它就必须带着完整的四元组(从哪个账户 / 给谁 / 多少 / 什么时候)**,
 *   否则策略引擎会拒绝执行这一步。这条不是文案要求,是结构要求 ——
 *   "事先明确告知每一笔资金去向和金额"只有在字段层面被强制,才谈得上被保证。
 */
export type EventStepDomain =
  /** 资金操作:锁定资金 / 定时任务(黄色) */
  | "fund"
  /** 外部服务操作:外部订购 / 打款(红色,需强验证) */
  | "external"
  /** 只读准备:查账单 / 查日程(绿色,方案生成时已完成) */
  | "read";

export interface EventFundsLeg {
  /** 出账账户(未指定时为空,由客户在确认卡上补) */
  fromAccountId: string | null;
  fromAccountLabel: string;
  /** 钱的去向:收款人 / 商户 / 用途专户 */
  toName: string;
  amount: number;
  currency: string;
  /** 计划发生时间(锁定到期 / 下单送达 / 定时执行) */
  scheduledAt: number | null;
}

export interface EventPlanStep {
  stepId: string;
  domain: EventStepDomain;
  domainLabel: string;
  /** 这一步做什么(一句话) */
  title: string;
  /** 为什么需要它(引用既有引擎的结论) */
  detail: string;
  /** 拟执行的能力名(只读步骤为 null) */
  capability: string | null;
  tier: "auto" | "confirm" | "strong_auth";
  tierLabel: string;
  /** 现在能不能执行(只读步骤已执行完毕) */
  executable: boolean;
  /** 资金去向披露(资金/外部步骤必填) */
  funds?: EventFundsLeg;
  /**
   * 资金步骤的方式(reserve = 预留锁定;schedule = 定时任务)。
   * ★ 为什么写在方案里而不是让编排器按话术猜:
   *   "这一步是现在锁一笔钱,还是到发薪日自动转一笔"是**方案自己的属性**,
   *   客户看到的就是它。若由话术临时决定,同一份方案会出现
   *   "按方案显示的是定时任务、执行时变成了立即锁定"这种不一致。
   */
  fundMode?: "reserve" | "schedule";
  /** 逐笔交代给客户的口径(去向 + 金额 + 时间) */
  disclosure: string;
  /** 依据(来自哪个既有引擎的哪条结论) */
  evidence: string[];
  /** 客户已确认执行过? */
  executed?: boolean;
}

export interface EventPlan {
  planId: string;
  eventId: string;
  eventTitle: string;
  eventKind: EventKind;
  occursAt: number;
  daysUntil: number;
  generatedAt: number;
  /** 方案有效期:过期后必须重新生成(期间账上余额可能已经变了) */
  expiresAt: number;
  steps: EventPlanStep[];
  /** ★ 方案里明确**不做**的事 —— 方案 ≠ 执行,这句话必须有机器可读的落点 */
  notDoing: string[];
  /** 方案用到的既有能力(跨场景引用的清单) */
  sources: string[];
  /** 一句话总览 */
  summary: string;
  /** 资金操作合计 / 外部服务操作合计(让客户一眼看到钱的总量) */
  fundTotal: number;
  externalTotal: number;
}

export interface EventFundStepInput {
  customerId: string;
  planId: string;
  stepId: string;
  /**
   * reserve = 预留(锁定)资金;schedule = 登记定时任务;release = 解开此前预留的资金。
   *
   * ★ 为什么"解开"也走同一个能力:它与预留是同一件事的两个方向 ——
   *   都改变"这笔钱还能不能用"。把它做成另一个能力,就会出现
   *   "预留要确认、解开不用确认"的不对称;而客户最不能接受的恰恰是
   *   "锁的时候问我了,解开的时候没问我"(比如他本想留着这笔钱)。
   */
  mode: "reserve" | "schedule" | "release";
  fromAccountId: string;
  toName: string;
  amount: number;
  currency: string;
  /** 预留到期时间 / 定时任务执行时间 / 解开时忽略 */
  scheduledAt: number;
  purpose: string;
  frozenPayloadHash?: string;
}

export interface EventFundStepReceipt {
  ok: boolean;
  planId: string;
  stepId: string;
  mode: "reserve" | "schedule" | "release";
  modeLabel: string;
  fromAccountId: string;
  fromAccountLabel: string;
  toName: string;
  amount: number;
  currency: string;
  /** 锁定到期时间(reserve) */
  reservedUntil: number | null;
  /** 定时任务 ID(schedule) */
  scheduleId: string | null;
  nextRunAt: number | null;
  /** ★ 账户可用余额在操作**之后**的数字 —— 客户最关心的就是"我还能用多少" */
  availableAfter: number;
  reference: string;
  wording: string;
}

export interface EventExternalStepInput {
  customerId: string;
  planId: string;
  stepId: string;
  merchantId: string;
  merchantName: string;
  item: string;
  amount: number;
  currency: string;
  /** 期望送达/发生时间 */
  scheduledAt: number;
  purpose: string;
  /** 资金来源账户(资金去向披露的一部分) */
  fromAccountId: string;
  frozenPayloadHash?: string;
}

export interface EventExternalStepReceipt {
  ok: boolean;
  planId: string;
  stepId: string;
  orderId: string;
  merchantId: string;
  merchantName: string;
  item: string;
  amount: number;
  currency: string;
  scheduledAt: number;
  /** ★ 下单已受理 ≠ 已完成服务;状态如实回填 */
  status: "submitted";
  statusLabel: string;
  /** 商户侧退订/改期政策(必须能讲给客户) */
  cancelPolicy: string;
  /** 资金来源与金额(逐笔披露) */
  fromAccountId: string;
  fromAccountLabel: string;
  reference: string;
  wording: string;
  /**
   * ★ 本次是幂等回放(这一步之前已经提交过,没有重复下单)。
   *
   * 为什么必须有这个字段:外部下单是**不可逆的外部后果** —— 重复订一次花,
   * 客户得自己去找商户退。银行侧按 (客户, 方案, 步骤) 做幂等,回执必须如实说明
   * "这是回放、没有再下一单",否则客户第二次确认后会以为又订了一单。
   */
  idempotentReplay?: boolean;
}

// ============================================================================
// 六、计划(DAG)—— 模型输出的唯一产物
// ============================================================================

/**
 * 执行计划。模型只输出这个结构(纯 JSON,不生成可执行代码),
 * 由确定性解释器执行。这是"沙箱条款"的正解:无代码执行,零攻击面。
 */
export interface Plan {
  planId: string;
  /** 对用户意图的复述 —— 用于澄清确认 */
  restatedIntent: string;
  /** 若存在关键信息缺失,必须先澄清(如收款人有多个候选) */
  needsClarification?: ClarificationRequest;
  nodes: PlanNode[];
  /** 声明本次计划不包含的敏感动作(用于审计与答辩展示) */
  declaredNoGo?: string[];
}

export interface PlanNode {
  nodeId: string;
  capability: string;
  /** 入参。允许通过 $ref 引用前置节点输出,但**不允许**字符串拼接 */
  input: Record<string, unknown>;
  /** 依赖的节点 ID(构成 DAG) */
  dependsOn: string[];
  /** 该节点失败时的处理 */
  onFailure: "abort" | "continue" | "compensate";
  /** 补偿节点(用于 Saga 回滚) */
  compensateWith?: { capability: string; input: Record<string, unknown> };
}

export interface ClarificationRequest {
  /** 需要用户补充的信息 */
  question: string;
  /** 结构化候选:让用户点选,而不是自由输入(交互体验关键) */
  candidates?: Array<{
    id: string;
    label: string;
    /** 副标题展示脱敏信息帮助用户区分同名收款人 */
    subLabel?: string;
    /** 用于消歧的特征,如"最近转账 3 次" */
    hint?: string;
  }>;
  /** 澄清类型 */
  kind: "disambiguate_payee" | "missing_amount" | "missing_account" | "confirm_amount" | "resolve_time";
}

// ============================================================================
// 七、审计(哈希链)
// ============================================================================

/**
 * 审计事件。追加式写入 + 哈希链,任一条被篡改则后续全链校验失败。
 * 这是"操作审计"条款的实现,也是答辩时最有说服力的一页。
 */
export interface AuditEvent {
  seq: number;
  ts: number;
  traceId: string;
  sessionId: string;
  customerId: string;
  channel: Channel;
  /**
   * ★ 本条事件的哈希公式版本(见 audit/hashChain.ts)。
   *
   * 为什么必须逐条记录、而不是全局一个常量:审计链要能同时校验**历史链**
   * 和新写入的事件。老事件(没有这个字段)只覆盖 seq/ts/type/payload/prevHash,
   * 于是"改归属字段(customerId/channel/traceId/sessionId)后哈希不变" ——
   * 取证时会得到"链完整未被篡改",而"是谁做的"已经被改掉了。
   * 新事件(v2)把归属四要素也纳入哈希;校验时按版本分别复算,
   * 并强制**版本只能前进**(v2 之后不得再出现 v1),否则把新事件"降级"即可绕过。
   */
  hashVersion?: number;
  /** 事件类型 */
  type:
    | "envelope_received"
    | "intent_parsed"
    | "plan_created"
    | "clarification_requested"
    | "capability_invoked"
    | "policy_evaluated"
    | "confirm_presented"
    | "strong_auth_requested"
    | "strong_auth_completed"
    | "payload_frozen"
    | "payload_hash_mismatch"
    | "execution_started"
    | "execution_completed"
    | "execution_failed"
    | "compensation_started"
    | "compensation_completed"
    | "injection_detected"
    | "hallucination_blocked"
    /**
     * ★ 检索专用事件(阶段 1/2)。
     *
     * 为什么检索也要入链:客户拿到的制度依据、以及"系统拒答过什么",
     * 本身就是可追溯的一部分 —— 事后复盘时必须能回答
     * 「当时按哪条条款回答的、置信度多少、是不是拒答了」。
     * 只记一次"检索发生了"没有价值,payload 里必须带命中条款与是否拒答。
     */
    | "policy_searched"
    | "memory_searched"
    /**
     * 请求被拒绝(如不合理请求、超出能力边界的请求)。
     *
     * ★ 为什么值得单独一类:和"阻断级操作"同理 ——
     *   被拒绝的请求**不会执行**,因此它自己没有机会写审计。
     *   而"系统拒绝过什么"恰恰是监管与风控最关心的一类证据:
     *   它能证明系统确实拦住了不该做的事,而不只是"没做"。
     */
    | "request_rejected"
    /**
     * ★ 理财场景专用事件(场景三)。
     *
     * 为什么这几类值得独立成事件类型,而不是塞进 execution_completed 的 payload:
     *   它们是**监管检查项**,而不是普通业务流水 ——
     *     · wealth_assessment_completed  "客户的风险等级是怎么来的"
     *     · wealth_consent_signed        "风险不匹配时,客户确实签过确认书"
     *     · wealth_risk_disclosure_sent  "推荐时到底有没有做风险提示"
     *   监管来查的时候问的就是这三件事,而它们必须能从审计里**直接检索**,
     *   不能靠翻 payload 猜。存成独立类型,一条 grep 就能出证据。
     */
    | "wealth_assessment_completed"
    | "wealth_consent_signed"
    | "wealth_consent_rejected"
    | "wealth_risk_disclosure_sent"
    /**
     * 到期续接方案已生成。
     *
     * ★ payload 里必须有 executed: false。
     *   监管和客诉要能直接查出:系统展示过哪些候选、排除了谁、有没有趁机申购。
     */
    | "wealth_rollover_plan_generated"
    /**
     * 客户选定了续接或明确不续投。
     *
     * ★ 这是意思表示,不是成交。没有对应的申购事件,就说明钱没动。
     */
    | "wealth_rollover_choice_recorded"
    /**
     * ★ 卡片管理场景专用事件(场景四)。
     *
     * 与理财那四类同理 —— 它们是**监管与内部风控的检查项**,不是普通业务流水:
     *   · card_loss_reported             "客户什么时候报的挂失,系统有没有立刻冻结"
     *   · card_limit_application_submitted  "客户申请的额度是多少、谁受理的、当前在哪个环节"
     *   · card_restriction_inquired      "客户问过限制原因,系统给出的原因是什么"
     *   · card_unblock_requested         "解除限制的申请" —— 与"已解除"是两件事
     *   · card_replacement_ordered       "补卡是否保留原卡号、客户是否被事先告知差异"
     *   · card_activation_completed      "新卡是否已激活、是否设置了交易密码"
     *   · card_credential_change_blocked "改手机号/改密码这类极高风险操作被拒绝代理"
     *
     * ★ 尤其注意 card_loss_reported 与 card_limit_application_submitted 两条:
     *   挂失是**紧急安全动作**,额度调整是**申请**。
     *   前者必须能在审计里看到"收到诉求到冻结成功"的先后顺序;
     *   后者必须保留"是申请,不是已生效"这个事实 —— 否则审计会污染成
     *   "系统给客户提了额",那是完全不同的一件事。
     */
    | "card_loss_reported"
    | "card_limit_application_submitted"
    | "card_restriction_inquired"
    | "card_unblock_requested"
    | "card_replacement_ordered"
    | "card_activation_completed"
    | "card_credential_change_blocked"
    /**
     * ★ 订阅代扣场景专用事件。
     *
     * 与理财/卡片那两类同理 —— 它们是**客诉与监管的检查项**,不是普通流水:
     *   · subscription_scanned            "系统是什么时候、按什么依据认出这笔代扣的"
     *                                     (关键词命中?固定周期金额?证据一并入链)
     *   · subscription_renewal_reminded   "扣费前有没有提醒过客户"(续费提醒的凭证)
     *   · subscription_cancelled          "取消的是哪一笔、什么时候生效、本期费用怎么办"
     *   · subscription_cancel_rejected    "客户想取消但没取消成" ——
     *                                     不存在的订阅 / 只能商户侧关闭 / 已经取消过。
     *     ★ 这一类最值得单独留痕:客户口径与系统口径不一致时(「我早就让你们关了」),
     *       能拿出的证据就是"当时系统明确告知过什么、为什么没办成"。
     */
    | "subscription_scanned"
    | "subscription_renewal_reminded"
    | "subscription_cancelled"
    | "subscription_cancel_rejected"
    /**
     * ★ 跨场景事件联动专用事件(新场景)。
     *
     * 与前面几类同理,它们是**合规检查项**而不是普通业务流水:
     *   · event_plan_generated       "系统在方案里到底承诺了什么、每一笔钱从哪去到哪、
     *                                 每一步是什么分级" —— 这是"事先明确告知"的凭据。
     *   · event_plan_step_confirmed  "客户确认的是**哪一步**、金额与去向是否与卡片一致" ——
     *                                 逐步确认的凭据。没有这条,就无法证明
     *                                 "资金操作与外部服务操作是分开确认的"。
     *   · event_external_order_placed "外部订单是谁授权的、金额多少、退订政策是什么" ——
     *                                 钱一旦离开银行体系,这条就是唯一的追溯起点。
     *   · event_plan_step_rejected   "客户想执行但没执行成" ——
     *                                 方案过期 / 缺资金去向 / 越级执行,三种都记在这。
     *   ★ 尤其 event_plan_generated 与 event_plan_step_confirmed 必须成对可查:
     *     合规要求的原话是"生成方案后,必须拆分为两步逐步请求用户确认",
     *     那么审计里就必须能分别看到"方案生成"与"某一步被确认"两个时刻。
     */
    | "event_plan_generated"
    | "event_plan_step_confirmed"
    | "event_plan_step_rejected"
    | "event_external_order_placed"
    /**
     * 上下文 / 材料比对 / 异常复核 —— 三项**业务场景之上的能力扩展**。
     *
     * ★ 它们不占场景编号:编号是"一类业务"的路标(转账 / 账单 / 理财 / 卡片 / 订阅代扣),
     *   而这三项都是**账单分析之上的深挖**(多份材料互相印证、要不要重扫、误报撤回)。
     *   给它们编号会让"第几个场景"这类说法只能靠人记住历史,而不是靠代码看出来。
     */
    | "document_compared"
    | "anomaly_review_planned"
    | "anomaly_withdrawn"
    /**
     * ★ 把一步分析工作派发给"受限专家"。
     *
     * 为什么单独成事件:事后必须能回答"这一步是谁做的、它当时能用哪些工具"。
     * 多 Agent 结构最大的风险是权限扩散,而权限扩散只有在**可检索的派发记录**面前
     * 才谈得上被审计。
     */
    | "specialist_dispatched"
    | "handoff_to_human"
    | "response_sent"
    /**
     * ★ 上机会话与鉴权(网关安全的基础设施事件)。
     *
     * 为什么它们必须进哈希链,而不是写一行服务器日志:
     *   ① `auth_session_issued` —— "这个身份是什么时候、以什么方式签发给谁的"。
     *      没有它,"某人用 CUST-DEMO-002 的令牌做了这些事"就无法证明身份从哪来;
     *   ② `auth_denied` —— **被拒绝的越权请求本身是证据**。客户拿别人的
     *      customerId 来查账单/动钱时,系统不仅要拒绝,还要能证明"当时拒绝了什么":
     *      请求声称是谁、令牌其实是谁、走的是哪条路径。这与 request_rejected
     *      同源 —— 被拒绝的请求不会执行,因此它自己没有机会写审计;
     *   ③ `auth_session_revoked` —— 登出与吊销也要留痕(否则无法回答
     *      "那次可疑操作发生时,这个会话还有效吗")。
     */
    | "auth_session_issued"
    | "auth_session_revoked"
    | "auth_denied"
    /**
     * ★ 响应装饰完成(交互体验层)。
     *
     * 为什么需要单独一类:办理流程、来源标注、主动建议是在 `response_sent`
     * **之后**拼进回复的,所以"客户实际看到的文本"与 response_sent 里那份并不相同。
     * 审计必须能读到最终文本 —— 否则监管拿到的证据与客户手里的截图对不上,
     * 那是最糟糕的一种不一致。
     */
    | "response_decorated"
    /**
     * ★ 提交点之前的干净中止(第 3 项:节点内中断)。
     *
     * 为什么必须与"执行失败"分开记:
     *   · `execution_failed` 是"试着做了,没做成" —— 可能已经改变了银行侧状态;
     *   · `execution_cancelled` 是"**根本没提交**" —— 余额与状态一个字节都没动。
     *   两者对账时的含义完全不同。这条事件的存在本身就是"干净中止"的证据:
     *   它只可能出现在 prepare 之后、commit 之前。
     *
     * payload 里必须带:op(prepare 的银行核心操作名)、preparedId、
     * phase("before_commit")、cause(user/timeout/operator)、reason 人话。
     */
    | "execution_cancelled"
    /**
     * ★ 影子模式下的新旧评分分歧(第 4 项第 3 步)。
     *
     * 影子模式**不接管裁决**:决定档位的仍是当前生效的评分器。
     * 但分歧必须留痕,否则"上新模型"这件事就变成了不可复核的跳跃。
     * payload 带:两边得分、两边档位、裁决者与挑战者标识。
     * ★ 特征与因子贡献**不在这里重复**:它们已经随同一条 traceId 的
     *   `policy_evaluated.payload.riskFactors` 落链。链条是证据不是日志,
     *   同一次评分的输入/输出只应出现一次,否则对账时要处理互相矛盾的两份副本。
     *
     * ★ 为什么评分记录本身**不**另设一个事件类型:
     *   评分已经随 `policy_evaluated` 落链(`payload.riskFactors`)。
     *   再写一条 `risk_scored` 只会让同一次评分在链上出现两次 ——
     *   审计链是证据,不是日志,重复的"事实"只会让对账更难。
     *   这次做的是把 `riskFactors` 补全:加上 `features`(模型输入)、
     *   `scorer`(谁打的分)、`shadow`(影子分),并在**全部四个裁决点**都写。
     */
    | "scorer_divergence"
    /**
     * ★ 事后结局标签回填(第 4 项第 1 步)。
     *
     * 标签不是系统自己猜的,而是**外部事实**回填进来的:
     * 欺诈确认 / 客户投诉 / 退款冲正。因此它必须能追溯到
     * "谁在什么时候、按哪个数据源、给哪一笔请求打了什么标签"。
     * payload 带:label(fraud_confirmed/complaint_filed/refund_settled)、
     * targetTraceId、windowDays、source(external_feed / synthetic_demo)。
     *
     * ★ 合成标签必须显式标成 synthetic_demo:它只用来自证"管道通了",
     *   不能用来声称模型有效。
     */
    | "outcome_labeled";
  /** 事件载荷(已脱敏) */
  payload: Record<string, unknown>;
  /** 前一条事件的哈希 */
  prevHash: string;
  /** 本条事件的哈希 = H(seq|ts|type|payload|prevHash) */
  hash: string;
}

export interface AuditPort {
  append(event: Omit<AuditEvent, "seq" | "prevHash" | "hash">): Promise<AuditEvent>;
  /** 校验哈希链完整性,返回第一个断点 */
  verifyChain(): Promise<{
    intact: boolean;
    brokenAtSeq?: number;
    legacyEvents?: number;
    /** 本实例是否只在写分片(说明这次校验覆盖的不是主链) */
    segmented?: boolean;
    /** 本次校验实际覆盖的事件条数 */
    checkedEvents?: number;
  }>;
  read(traceId: string): Promise<AuditEvent[]>;
}

// ============================================================================
// 八、Agent 回合结果
// ============================================================================

/** 一个回合(用户一条消息 → Agent 一次响应)的最终结果 */
export interface AgentTurnResult {
  turnId: string;
  traceId: string;
  /** 面向用户的自然语言回复(已通过 I3 幻觉校验) */
  reply: string;
  /** 富卡片(渠道不支持时降级为文本) */
  card?: ConfirmCard;
  /** 反诈提醒块(标题 / 反话术提示 / 核实清单);有富卡片能力的渠道据此画警示卡 */
  fraud?: import("./security/antiFraud.ts").FraudCardBlock;
  /** 需要用户做的动作 */
  promptFor?: {
    kind: "confirm" | "strong_auth" | "clarify" | "none";
    refId?: string;
    candidates?: ClarificationRequest["candidates"];
  };
  /** 本次裁决摘要(供审计面板与答辩展示) */
  policySummary?: PolicyReason[];
  /** 阻断/转人工等终端状态 */
  terminal?: { kind: "denied" | "handoff" | "completed"; detail?: string };
  /**
   * ★ 办理流程(从本轮的审计事件派生,见 agent/flowTrace.ts)。
   *   界面据此画出"正在办理"的步骤链路,文本渠道则由 reply 里同源的文字承载。
   */
  flow?: FlowTrace;
  /** ★ 本轮涉及的数字与规则的出处(来源/主体/时效/计算过程) */
  citations?: SourceCitation[];
  /** ★ 个性化主动建议(确定性规则产生,至多 3 条) */
  suggestions?: ProactiveSuggestion[];
  /** ★ 需要单独摆出来的可视块(材料比对 / 复核决策 / 误报撤回) */
  visual?: VisualBlock;
}

// ============================================================================
// 九、导出 zod 类型(供能力定义使用)
// ============================================================================

export type { z };
