/**
 * 组装根(Composition Root)
 *
 * 这是整个应用**唯一**把各部分拼起来的地方。
 * 依赖方向始终向内:core 不知道 llm 的存在,llm 不知道 bankcore 的存在,
 * 所以模型可以替换、银行核心可以替换,而核心安全逻辑一行不改。
 */

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";

import {
  AgentOrchestrator,
  buildDefaultRegistry,
  type AuthProof,
  type ChannelCapabilities,
  type Channel,
  type CustomerProfile,
  type IntentParserPort,
  type MessageEnvelope,
} from "../../core/src/index.ts";
import { MockBankPort, buildDemoWorld, type DemoWorld } from "../../bankcore/src/mock.ts";
import { parseIntent } from "../../llm/src/intentParser.ts";
import {
  readLlmConfigFromEnv,
  selectLlmProvider,
  type LlmSelection,
} from "../../llm/src/factory.ts";
import { HashChainAudit } from "../../core/src/audit/hashChain.ts";
import { buildCustomerDesk, type CustomerDesk } from "./desk.ts";
import {
  buildTurnDecoration,
  deriveTemplate,
  flowFamilyOf,
  lastConfirmCardOf,
  templateToSay,
} from "../../core/src/agent/flowTrace.ts";
import type {
  ProactiveSuggestion,
  SavedFlowTemplate,
  SuggestionFacts,
} from "../../core/src/agent/turnExtras.ts";
import type { AuditEvent, CancellationState } from "../../core/src/types.ts";
import { buildBillHealth, findIdleDemandInflow, fmtDate } from "../../core/src/capabilities/billAnalysis.ts";
import { RuleSuggestionEngine } from "../../core/src/agent/suggestion.ts";
import { deriveOperationStatus, type OperationStatus } from "../../core/src/agent/operationStatus.ts";
import { PersonalizationStore } from "./personalization.ts";
import { AuthSessionStore, SessionJournal } from "./sessions.ts";
import { createRetrievalPort, loadPolicyCorpus } from "./retrieval/corpusLoader.ts";
import { createMemoryIndex } from "./retrieval/memoryIndex.ts";

// ============================================================================
// 渠道能力表
// ============================================================================

/**
 * 各渠道的能力与风险等级。
 *
 * ★ 这是"渠道分级"的数据来源:同一笔转账在 APP 里可以人脸确认后执行,
 *   在 IM 里则必须跳回安全渠道 —— 因为 IM 消息可截图、可转发、会话易被接管。
 */
export const CHANNEL_CAPABILITIES: Record<Channel, ChannelCapabilities> = {
  app: { risk: "low", richCard: true, biometric: true, deepLink: true, interactive: true },
  web: { risk: "medium", richCard: true, biometric: false, deepLink: true, interactive: true },
  im: { risk: "high", richCard: false, biometric: false, deepLink: true, interactive: true },
  voice: { risk: "high", richCard: false, biometric: false, deepLink: false, interactive: false },
};

// ============================================================================
// 客户资料
// ============================================================================

export function buildProfile(customerId: string, world: DemoWorld): CustomerProfile {
  const isPrimary = customerId === world.primaryCustomerId;

  if (isPrimary) {
    return {
      customerId,
      displayName: "张先生",
      riskProfile: {
        // 从演示数据推出的画像基线:常见转账在几百到几千元
        transferAmountP50: 1_500,
        transferAmountP95: 5_800,
        frequentPayees: [world.refs.mom.payeeId, world.refs.landlord.payeeId, world.refs.colleague.payeeId],
        // 常用时段:7–22 点
        activeHours: [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22],
      },
      trustedDeviceBound: true,
      preferences: {
        // 客户自己设定的更严格阈值:超过 2 万必须强验证
        alwaysStrongAuthAbove: 20_000,
        coolDownReminder: true,
      },
      security: { restricted: false },
    };
  }

  return {
    customerId,
    displayName: "赵女士",
    riskProfile: {
      transferAmountP50: 800,
      transferAmountP95: 3_000,
      frequentPayees: [],
      activeHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21],
    },
    trustedDeviceBound: true,
    preferences: {},
    security: { restricted: false },
  };
}

// ============================================================================
// 强验证回执验签
// ============================================================================

/**
 * 强验证回执的签发与验签。
 *
 * ★ 架构要点:Agent **不实现**验证逻辑,也不接触生物特征数据。
 *   验证在原生安全环境(手机银行 App / U 盾 / 短信网关)完成,由可信方签发回执。
 *   Agent 只做转交校验 —— 因此即使 Agent 被完全攻破,也无法伪造一份验证回执。
 *
 *   生产环境:非对称签名(HSM 中的私钥签发,Agent 侧只有公钥)。
 *   演示环境:HMAC 模拟同一语义。
 *
 *   @internal 仅用于演示 —— 真实签发方是安全环境,不是 Agent。
 */
export const DEMO_AUTH_SECRET = "demo-hsm-secret-not-for-production";

/**
 * 演示环境的默认登录口令。
 *
 * ★ 公开写在代码里是**刻意的**:它不是秘密,也不能被当成秘密用。
 *   它的作用是让"登录 → 签发会话 → 身份只来自令牌"这条链在演示里可跑通;
 *   要换口令就设 `AUTH_DEMO_PASSWORD`(或按客户分别设 `..._PRIMARY` / `..._SPOUSE`)。
 *   生产环境必须替换成真实凭据校验 —— 见 verifyCredential 的说明与 README。
 */
export const DEMO_DEFAULT_PASSWORD = "demo-pass";

export function signAuthProof(input: {
  method: AuthProof["method"];
  boundPayloadHash: string;
  now?: number;
  ttlMs?: number;
}): AuthProof {
  const now = input.now ?? Date.now();
  const ttlMs = input.ttlMs ?? 120_000;
  const nonce = randomUUID();
  const issuer = "demo-secure-enclave";
  const issuedAt = now;
  const expiresAt = now + ttlMs;

  const signature = createHmac("sha256", DEMO_AUTH_SECRET)
    .update([issuer, input.method, input.boundPayloadHash, issuedAt, expiresAt, nonce].join("|"))
    .digest("hex");

  return {
    method: input.method,
    issuer,
    boundPayloadHash: input.boundPayloadHash,
    issuedAt,
    expiresAt,
    signature,
    nonce,
  };
}

export async function verifyAuthProof(
  proof: AuthProof,
  expectedPayloadHash: string,
  now: number = Date.now(),
): Promise<boolean> {
  // 1. 有效期
  if (now > proof.expiresAt) return false;
  if (now < proof.issuedAt - 5000) return false;

  // 2. ★ 回执必须绑定到本次载荷 —— 防止验证通过后被替换载荷(TOCTOU)
  if (proof.boundPayloadHash !== expectedPayloadHash) return false;

  // 3. 签名校验
  const expected = createHmac("sha256", DEMO_AUTH_SECRET)
    .update([proof.issuer, proof.method, proof.boundPayloadHash, proof.issuedAt, proof.expiresAt, proof.nonce].join("|"))
    .digest("hex");

  return timingSafeEqualHex(expected, proof.signature);
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * 结构化动作(按钮点击)在会话回放里该记成什么。
 *
 * ★ 按钮点击进站时 `text` 是空的(它不是一句话,是一个动作)。
 *   若原样落盘,回放里会出现一条**空的用户消息** —— 客户看到一段空白,
 *   更糟的是"再办一次"要预填最后一轮用户原话,而它是个空串。
 *   所以把动作翻成一句人话:客户当时确实做了这个动作。
 */
function actionLabelForReplay(action: MessageEnvelope["action"]): string {
  switch (action?.kind) {
    case "confirm":
      return "确认";
    case "cancel":
      return "取消";
    case "select":
      return "选择";
    case "deep_link_return":
      return "完成身份验证后返回";
    default:
      return action?.value ?? "";
  }
}

/** 演示辅助:签发一份签名错误的回执(用于演示"伪造回执会被拒绝") */
export function forgeAuthProof(proof: AuthProof): AuthProof {
  return { ...proof, signature: proof.signature.replace(/^./, (c) => (c === "a" ? "b" : "a")) };
}

/**
 * 从能力返回值里挑出"客户可以拿去查这一笔"的编号。
 *
 * ★ 优先级固定为 reference → applicationId → orderId → transferId(31 文档 §3.3):
 *   不同能力用的字段名不同(转账用 reference、申请类用 applicationId/orderId、
 *   旧的转账回执用 transferId),但客户看到的是同一件事 —— 一个能报给客服的编号。
 *   统一在这里收口,免得每个调用点各挑一个、挑漏了就成了空台账。
 */
function pickOperationReference(data: unknown): string | undefined {
  if (data == null || typeof data !== "object") return undefined;
  const record = data as Record<string, unknown>;
  for (const key of ["reference", "applicationId", "orderId", "transferId"]) {
    const value = record[key];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

// ============================================================================
// 应用组装
// ============================================================================

export interface AppOptions {
  /** 强制离线(不调用外部模型) */
  offline?: boolean;
  /** 审计日志目录 */
  auditDir?: string;
  /** 个性化数据目录(常用流程 + 历史业务记录) */
  personalizationDir?: string;
  /** 会话记录目录(回放用;进程重启后仍在) */
  sessionsDir?: string;
  /** 上机会话(身份令牌)存放目录;不传则与会话记录同目录 */
  authDir?: string;
  /** 会话签名密钥(生产环境来自密钥管理;不传则本进程随机) */
  authSecret?: string;
  /** 时钟注入(测试用) */
  now?: () => number;
  /** 固定在某个时间点(演示可复现) */
  fixedNow?: number;
  env?: NodeJS.ProcessEnv;
}

/** 凭据校验结论(★ 对外只有"行/不行"两种;细节只进审计,不回给调用者) */
export interface CredentialVerdict {
  ok: boolean;
  /** 失败/成功的原因标识(审计用):unknown_customer / bad_password / human_required */
  reason: string;
  /** 成功时的凭据类别(审计用):demo_password */
  kind?: string;
  /** 成功时的显示名(界面用) */
  displayName?: string;
}

export interface App {
  orchestrator: AgentOrchestrator;
  world: DemoWorld;
  bank: MockBankPort;
  audit: HashChainAudit;
  llm: LlmSelection;
  /**
   * 上机会话存储(**身份的唯一签发处**)。
   *
   * ★ 放在 app 上而不是网关模块里:测试、验证脚本、CLI 都需要能直接
   *   "签发/撤销一个会话"来构造场景,而不必去启动一个 HTTP 服务。
   *   网关只是它的调用者之一,不是它的主人。
   */
  auth: AuthSessionStore;
  /** 应用时钟(与会话、审计、编排器共用同一个时间源,测试可注入) */
  now(): number;
  /**
   * 校验一次登录凭据。
   *
   * ★ 关键设计:本方法**不认识 HTTP** —— 登录节流、Cookie、审计事件都在网关,
   *   这里只回答"这个客户号 + 这个口令对不对"。这样"谁能成为谁"的判定
   *   与"怎么把身份发出去"各自只有一处实现,也便于测试直接调用。
   */
  verifyCredential(customerId: string, password: string): Promise<CredentialVerdict>;
  /** 个性化存储(常用流程的落盘处,界面与验证脚本都会用到) */
  personalization: PersonalizationStore;
  /** 会话记录(每轮 user/agent 原话 + 标题 + 状态;历史列表/回放的数据源) */
  sessions: SessionJournal;
  /** 制度检索索引(语料缺失时为 null;policy.search 会如实说明"检索未就绪") */
  policyIndex: import("../../core/src/index.ts").PolicyIndex | null;
  /** 便捷:构造消息信封 */
  envelope(input: {
    channel: Channel;
    text: string;
    customerId?: string;
    sessionId?: string;
    channelUserId?: string;
    /** ★ 渠道侧的业务流水号:重试/重放时带同一个值,才会被幂等保护接住 */
    messageId?: string;
    /**
     * ★ 上游中止意图(第 3 项:节点内中断)。
     *
     *   为什么必须在这里显式声明,而不是"调用方多塞一个字段"就行:
     *   实测踩到过 —— 网关把 `cancellation` 用对象展开塞进入参,
     *   而**对象展开不触发 TS 的多余属性检查**,于是编译期一声不响,
     *   运行期这个字段被 envelope 丢掉:取消意图永远到不了提交点,
     *   客户按下取消后钱照转,而且没有任何报错。
     *   参数类型里写出来,才是这条链路唯一的"接口真相"。
     */
    cancellation?: CancellationState;
  }): MessageEnvelope;
  /** 演示/测试辅助:读取客户当前的风险测评结论(理财场景) */
  wealthProfile(customerId: string): Promise<import("../../core/src/types.ts").WealthRiskProfile>;
  /** 客户已保存的常用流程 */
  listFlows(customerId: string): Promise<SavedFlowTemplate[]>;
  /** 保存常用流程(幂等) */
  saveFlow(customerId: string, template: SavedFlowTemplate): Promise<SavedFlowTemplate>;
  /** 删除常用流程 */
  removeFlow(customerId: string, templateId: string): Promise<boolean>;
  /** 把常用流程实例化成一句可直接发送的话 */
  instantiateFlow(customerId: string, templateId: string): Promise<string | null>;
  /**
   * 从一个**已执行成功**的回合派生常用流程模板(自动保存与手动保存共用)。
   *
   * 返回 null 表示:这一轮没有成功办结的能力,或该能力属于查询类不值得存。
   */
  deriveFlowForTrace(input: {
    traceId: string;
    customerId: string;
    sessionId: string;
  }): Promise<SavedFlowTemplate | null>;
  /** 客户明确要求时,把最近一次办成的事存为常用流程 */
  saveRecentFlow(input: {
    customerId: string;
    sessionId: string;
  }): Promise<{ saved: SavedFlowTemplate | null; reason?: string }>;
  /** 首页个性化:常用流程 + 智能建议(含冷却过滤) + 办事台 */
  personalizationView(
    customerId: string,
    sessionId?: string,
  ): Promise<{
    flows: Array<SavedFlowTemplate & { say: string }>;
    history: Array<{ ts: number; family: string; capability: string; amount?: number; subject?: string; completed: boolean }>;
    suggestions: Array<ProactiveSuggestion & { say: string }>;
    desk: CustomerDesk;
  }>;
}

export async function createApp(options: AppOptions = {}): Promise<App> {
  const env = options.env ?? process.env;

  // ---- 演示时钟:固定则数据可复现 ----
  const now = options.now ?? (options.fixedNow != null ? () => options.fixedNow! : () => Date.now());

  // ---- 银行核心(内存账本) ----
  const world = buildDemoWorld({ now: now() });
  const bank = new MockBankPort(world);

  // ---- 审计(哈希链,JSONL 落盘) ----
  const auditDir = options.auditDir ?? resolve(process.cwd(), env["AUDIT_DIR"] ?? "./var/audit");
  const audit = new HashChainAudit({ auditDir });
  const loaded = await audit.loadFromDisk();
  if (loaded.loaded > 0) {
    // 续写既有链;若链已损坏则报警(不静默覆盖,这是审计的基本要求)
    if (!loaded.intact) {
      console.warn(
        `⚠️  审计日志链路完整性校验失败,已加载 ${loaded.loaded} 条记录但存在断点。请检查 ${auditDir}`,
      );
    }
  }

  // ---- 大模型 ----
  const llmConfig = readLlmConfigFromEnv(env);
  if (options.offline) llmConfig.offline = true;
  const llm = selectLlmProvider(llmConfig);

  // ---- 意图解析器端口(core 不依赖具体模型实现) ----
  const intentParser: IntentParserPort = {
    parse: async (input) => {
      const result = await parseIntent({
        provider: llm.provider,
        userText: input.userText,
        history: input.history,
        context: input.context,
        ...(input.sequentialHint ? { sequentialHint: true } : {}),
      });
      return {
        ok: result.ok,
        ...(result.parsed ? { parsed: result.parsed } : {}),
        ...(result.error ? { error: result.error } : {}),
        provider: result.provider,
        ...(result.latencyMs != null ? { latencyMs: result.latencyMs } : {}),
        ...(result.usage ? { usage: result.usage } : {}),
      };
    },
  };

  // ---- 能力注册表 ----
  const registry = buildDefaultRegistry();

  /**
   * ---- 检索端口(阶段 1 制度 + 阶段 2 记忆)----
   *
   * ★ 语料缺失不能让整个应用起不来:转账/账单/卡片与它无关。
   *   加载失败时 policy 部分保持 undefined,policy.search 会如实回答"检索未就绪",
   *   而不是编一条条款出来。记忆检索不依赖语料文件,只要台账/会话在就能用。
   */
  let policyIndex: import("../../core/src/index.ts").PolicyIndex | null = null;
  try {
    policyIndex = (await loadPolicyCorpus()).index;
  } catch {
    policyIndex = null;
  }

  /**
   * 记忆索引的数据源全部来自宿主(台账 / 会话 / 批注 / 材料)。
   * ★ 每个数据源都以 customerId 为入参 —— 跨客户隔离在**数据入口**完成,
   *   而不是在结果上过滤(后者容易漏)。
   */
  const memoryIndex = createMemoryIndex({
    ledger: (customerId) => personalization.ledger(customerId),
    sessions: (customerId) => sessions.list(customerId),
    ...(typeof (bank as unknown as { listAnnotations?: unknown }).listAnnotations === "function"
      ? {
          annotations: (customerId: string) =>
            (
              bank as unknown as {
                listAnnotations: (id: string, limit?: number) => Array<{
                  annotationId: string;
                  title: string;
                  amount?: number;
                  note?: string;
                  tags?: string[];
                  createdAt: number;
                }>;
              }
            ).listAnnotations(customerId, 50),
        }
      : {}),
    documents: (customerId) => bank.listDocuments(customerId),
    now: () => now(),
  });

  const retrieval: import("../../core/src/index.ts").RetrievalPort | undefined = {
    ...(policyIndex ? createRetrievalPort(policyIndex) : {}),
    searchMemory: (input) => memoryIndex.searchMemory(input),
  } as import("../../core/src/index.ts").RetrievalPort;

  // ---- 个性化:常用流程与历史业务记录(落盘,进程重启后仍在) ----
  const personalizationDir =
    options.personalizationDir ?? resolve(process.cwd(), env["PERSONALIZATION_DIR"] ?? "./var/personalization");
  const personalization = new PersonalizationStore(personalizationDir);

  // ---- 会话记录:每轮 user/agent 原话(落盘,供历史列表与只读回放) ----
  const sessionsDir = options.sessionsDir ?? resolve(process.cwd(), env["SESSIONS_DIR"] ?? "./var/sessions");
  const sessions = new SessionJournal(sessionsDir);

  /**
   * ---- 上机会话(身份令牌)----
   *
   * ★ 落盘位置与会话记录分开命名、可以同一个目录:前者是"谁在线上"的凭据状态,
   *   后者是"说过什么"的业务记录。混在一起会让"清掉回放记录"顺带把登录状态也清了。
   */
  const authDir = options.authDir ?? resolve(process.cwd(), env["AUTH_DIR"] ?? sessionsDir);
  const auth = new AuthSessionStore({
    dir: authDir,
    ...(options.authSecret ? { secret: options.authSecret } : {}),
    now,
  });

  const suggestionEngine = new RuleSuggestionEngine(2);

  /**
   * 取某个收款人/产品名下客户平时用的别名(「老妈」「房东」)。
   *
   * ★ 用途只有一个:让常用流程的名字与客户的口语对得上。
   *   客户存的是「给 王秀兰 转账」,但他下次说的是「用一下给老妈转账」——
   *   不带别名,这条常用流程就变成了"存了却认不出来"。
   */
  function payeeAliases(name: string): string[] {
    if (!name) return [];
    for (const p of world.payees.values()) {
      if (p.name === name) return [...p.aliases];
    }
    return [];
  }

  /** 本轮与同一会话最近几轮的事件(同一个 traceId 的放一起,按 seq 升序) */
  async function sessionEventsAround(
    traceId: string,
    customerId: string,
    sessionId: string,
  ): Promise<{ current: AuditEvent[]; previous: AuditEvent[] }> {
    // ★ 走审计链本身(内存链 + 磁盘恢复),而不是某个进程内的会话缓存:
    //   手动保存可能来自另一个进程/另一次启动,缓存里是空的 ——
    //   而"客户上次存的那条常用流程"必须能被它自己找回来。
    const all = (await audit.readAll()).filter((e) => e.customerId === customerId);
    const current = all.filter((e) => e.traceId === traceId).sort((a, b) => a.seq - b.seq);
    if (current.length === 0) return { current: [], previous: [] };
    const start = current[0]!.seq;
    const previous = all.filter((e) => e.seq < start && e.sessionId === sessionId).sort((a, b) => a.seq - b.seq);
    return { current, previous };
  }

  /** 把别名并进模板(名字进 name、匹配进 fixed),只存名字,不存账号 */
  function withAliases(tpl: SavedFlowTemplate): SavedFlowTemplate {
    const source = tpl.fixed["收款人"] ?? tpl.fixed["产品"] ?? "";
    const aliases = payeeAliases(source);
    if (aliases.length === 0) return tpl;
    return { ...tpl, name: `${tpl.name}(${aliases.join("/")})`, fixed: { ...tpl.fixed, 别名: aliases.join("/") } };
  }

  /**
   * 从一次**已执行成功**的回合派生常用流程模板。
   *
   * ★ 为什么必须有这个函数(而不是各处各写一遍):实测踩到两次同源缺陷 ——
   *   资金类操作天然跨两轮(第 1 轮展示确认卡、第 2 轮确认后才执行),
   *   只拿"执行那一轮"的事件,是拿不到收款人与金额的:
   *     · 自动保存路径漏了 → 模板退化成「给 {收款人} 转 {金额} 元」;
   *     · 手动保存接口漏了 → 客户点"存为常用流程",存下来的是一条**没有对象、没有金额**的空壳,
   *       而且它还会按 templateId 覆盖掉自动保存那条好的。
   *   现在两条路径共用这一个实现,派生规则与别名富化都只有一处。
   */
  /**
   * 从一次**已执行成功**的回合派生常用流程模板(自动保存与手动保存共用)。
   *
   * ★ 为什么必须有这个函数(而不是各处各写一遍):实测踩到两次同源缺陷 ——
   *   资金类操作天然跨两轮(第 1 轮展示确认卡、第 2 轮确认后才执行),
   *   只拿"执行那一轮"的事件,是拿不到收款人与金额的:
   *     · 自动保存路径漏了 → 模板退化成「给 {收款人} 转 {金额} 元」;
   *     · 手动保存路径漏了 → 客户点"存为常用流程",存下来的是一条**没有对象、没有金额**的空壳,
   *       而且它还会按 templateId 覆盖掉自动保存那条好的。
   *   现在两条路径共用这一个实现,派生规则与别名富化都只有一处。
   */
  function deriveFlowFromEvents(input: {
    current: AuditEvent[];
    previous: AuditEvent[];
  }): SavedFlowTemplate | null {
    const executed = [...input.current]
      .reverse()
      .find((e) => e.type === "execution_completed" && e.payload?.["capability"]);
    if (!executed) return null;
    const capability = String(executed.payload["capability"]);
    const family = flowFamilyOf(capability);
    if (!family.saveable) return null;
    const card =
      lastConfirmCardOf(input.current) ??
      lastConfirmCardOf(input.previous.filter((e) => (e.payload?.["capability"] ?? "") === capability));
    return withAliases(deriveTemplate({ capability, card, flowLabel: family.label, now: now() }));
  }

  /** 读审计链得到快照后派生(供网关的手动保存接口使用) */
  async function deriveFlowFromAudit(input: {
    traceId: string;
    customerId: string;
    sessionId: string;
  }): Promise<SavedFlowTemplate | null> {
    const { current, previous } = await sessionEventsAround(input.traceId, input.customerId, input.sessionId);
    return deriveFlowFromEvents({ current, previous });
  }

  /**
   * "把刚才那个存成常用流程" —— 客户一句话就能存。
   *
   * ★ 找的是**这个会话里最近一次真的办成的事**,而不是"最近一句话"。
   *   客户往往在办完之后过了几轮才想起来要存,这时最后一轮可能只是查了个余额。
   *   按"最近一次成功执行"找,才符合他心里的"刚才那个"。
   */
  async function saveRecentFlow(input: {
    customerId: string;
    sessionId: string;
  }): Promise<{ saved: SavedFlowTemplate | null; reason?: string }> {
    const all = await audit.readAll();
    const mine = all
      .filter((e) => e.customerId === input.customerId && e.sessionId === input.sessionId)
      .sort((a, b) => b.seq - a.seq);

    const executed = mine.find((e) => e.type === "execution_completed" && e.payload?.["capability"]);
    if (!executed) {
      return { saved: null, reason: "这个会话里还没有成功办成的事,先办一件再存。" };
    }

    const { current, previous } = await sessionEventsAround(executed.traceId, input.customerId, input.sessionId);
    const template = deriveFlowFromEvents({ current, previous });
    if (!template) {
      const cap = String(executed.payload["capability"]);
      return {
        saved: null,
        reason: `「${flowFamilyOf(cap).label}」是查询类操作,不需要存成常用流程。`,
      };
    }
    const saved = await personalization.saveFlow(input.customerId, template);
    return { saved };
  }



  /**
   * 组装建议所需的事实快照。
   *
   * ★ 这里刻意用**银行侧真实数据**而不是编造的统计:
   *   本月支出从流水算、可用余额从账户主档读、常用流程从落盘的客户数据读。
   *   一条建立在假数据上的"贴心建议"比不提建议更糟 ——
   *   客户会发现数字对不上,然后开始怀疑所有数字。
   */
  async function buildFacts(customerId: string, now: number): Promise<SuggestionFacts> {
    const monthStart = (() => {
      const s = new Date(now).toLocaleDateString("en-CA", { timeZone: "Asia/Shanghai" });
      const [y, m] = s.split("-").map((x) => Number(x));
      return Date.UTC(y ?? 1970, (m ?? 1) - 1, 1) - 8 * 3600 * 1000;
    })();

    const [txs, accounts, flows, profile, recent, holdings] = await Promise.all([
      bank.listTransactions(customerId, { from: monthStart, to: now, direction: "out", limit: 300 }),
      bank.listAccounts(customerId),
      personalization.listFlows(customerId),
      bank.getRiskProfile(customerId),
      personalization.recentCapabilities(customerId, 30 * 24 * 3600 * 1000, now),
      bank.listWealthHoldings(customerId),
    ]);
    const maturityTimes = holdings
      .map((h) => h.maturityAt)
      .filter((t): t is number => typeof t === "number" && t >= now - 24 * 3600 * 1000)
      .sort((a, b) => a - b);
    const soonestMaturity = maturityTimes[0];
    const soonestMaturityDays =
      soonestMaturity == null ? null : Math.ceil((soonestMaturity - now) / (24 * 3600 * 1000));

    const demandAccounts = accounts.filter((a) => a.type === "current" && a.status === "active");
    const demandAvailable = Math.round(demandAccounts.reduce((s, a) => s + a.availableBalance, 0) * 100) / 100;
    const demandIds = new Set(demandAccounts.map((a) => a.accountId));
    const history = await bank.fetchForAnalysis(customerId, { from: now - 100 * 24 * 3600 * 1000, to: now });
    const health = buildBillHealth(history, now);
    const idle = findIdleDemandInflow(
      history
        .filter((t) => t.direction === "in" && demandIds.has(t.accountId))
        .map((t) => ({ amount: t.amount, ts: t.ts, counterpartyName: t.counterpartyName })),
      demandAvailable,
      now,
    );

    return {
      customerId,
      displayName: customerId === world.primaryCustomerId ? "张先生" : "赵女士",
      now,
      monthExpense: Math.round(txs.reduce((s, t) => s + t.amount, 0) * 100) / 100,
      monthExpenseCount: txs.length,
      availableBalance: Math.round(accounts.reduce((s, a) => s + a.availableBalance, 0) * 100) / 100,
      savedFlows: await Promise.all(
        flows.map(async (f) => ({
          templateId: f.templateId,
          name: f.name,
          useCount: f.useCount,
          ...(f.lastUsedAt != null ? { lastUsedAt: f.lastUsedAt } : {}),
          say: templateToSay(f),
        })),
      ),
      recentCapabilities: recent,
      sessionCapabilities: [],
      wealthAssessed: profile.assessed && !profile.expired,
      soonestMaturityDays,
      billHealth: {
        tag: health.tag,
        tagLabel: health.tagLabel,
        diningMonthlyAvg: health.diningMonthlyAvg,
        surplusMonthlyAvg: health.surplusMonthlyAvg,
        windowLabel: health.windowLabel,
        reason: health.reason,
      },
      idleCash: idle
        ? {
            amount: idle.amount,
            counterpartyName: idle.counterpartyName,
            atLabel: fmtDate(idle.ts),
            ageHours: Math.floor(idle.ageMs / (3600 * 1000)),
            demandAvailable: idle.demandAvailable,
            threshold: idle.threshold,
          }
        : null,
    };
  }

  /**
   * ★ 回合装饰器:把"这一轮"加工成客户看得懂的样子,并顺手记进客户的历史。
   *
   * 三件事在这里收口,而不是散落在业务链路里:
   *   ① 办理流程(从审计事件派生 —— 与审计不可能不一致);
   *   ② 数字与规则的出处;
   *   ③ 个性化建议 + 常用流程的"自动记住"。
   */
  const turnDecorator = async (input: {
    result: import("../../core/src/types.ts").AgentTurnResult;
    extras: import("../../core/src/agent/turnExtras.ts").TurnExtras;
    events: import("../../core/src/types.ts").AuditEvent[];
    previousEvents: import("../../core/src/types.ts").AuditEvent[];
    envelope: MessageEnvelope;
    record: (entry: {
      capability?: string;
      family?: string;
      amount?: number;
      subject?: string;
      completed: boolean;
      reference?: string;
      /** 台账字段:与 core 的 TurnDecorator.record 保持同一形状 */
      sessionId?: string;
      status?: import("../../core/src/agent/operationStatus.ts").OperationStatus;
      statusLabel?: string;
      detail?: string;
      opId?: string;
      traceId?: string;
      createdAt?: number;
    }) => Promise<void>;
  }): Promise<import("../../core/src/types.ts").AgentTurnResult> => {
    const nowTs = now();
    const extras = input.extras;

    // 建议冷却:同一条建议 6 小时内只推一次(客户没点就是不需要,再推是打扰)
    const rawSuggestions = extras.suggestions ?? [];
    const allowed = await personalization.filterSuggestions(input.envelope.customerId, rawSuggestions, nowTs);
    if (allowed.length > 0) await personalization.markSuggestionsShown(input.envelope.customerId, allowed.map((s) => s.id), nowTs);

    const decoration = buildTurnDecoration({
      reply: input.result.reply,
      promptKind: input.result.promptFor?.kind ?? "none",
      terminal: input.result.terminal,
      extras,
      events: input.events,
      previousEvents: input.previousEvents,
      suggestions: allowed,
      now: nowTs,
    });

    // ---- 客户历史 / 操作台账:本轮真正办成了什么、到哪一步了 ----
    const cardFields = extras.confirmCard?.fields ?? [];
    const amountField = cardFields.find((f) => /金额/.test(f.label));
    const subjectField = cardFields.find((f) => /收款人|产品|卡片/.test(f.label));
    const amount = amountField ? Number(String(amountField.value).replace(/[^\d.]/g, "")) : undefined;

    /**
     * ★ 台账的"事实来源"是审计事件,不是文案:
     *   · execution_completed / execution_failed 带着能力的**完整返回值**(I3);
     *   · policy_evaluated 带着被裁决的能力名(被拦截的请求没有执行事件,只能从这儿取)。
     *
     *   为什么要从这里取而不是从 extras 取:extras 只记了"能力名",
     *   而业务态要看能力**返回了什么**(流水号、目标额度、到账时效…)。
     */
    const executedEvent = [...input.events]
      .reverse()
      .find((e) => e.type === "execution_completed" || e.type === "execution_failed");
    /**
     * ★ `execution_cancelled` 刻意**不进台账**(第 3 项),这不是漏了:
     *   提交点之前的中止意味着"什么都没发生" —— 余额未动、账户状态未变。
     *   把它写成一条业务记录,客户会在历史里看到一笔"转账 · 某人",
     *   然后以为需要去核对或撤销它;而事实是根本没有这笔业务。
     *   证据不会丢:它照样在审计哈希链里(`execution_cancelled`),
     *   监管/客服按 traceId 一查就能看到"何时被谁中止、为什么"。
     *   台账回答"我办过什么",审计回答"系统经历过什么" —— 两者口径不同。
     */
    const evaluatedEvent = [...input.events].reverse().find((e) => e.type === "policy_evaluated");
    const evaluatedCapability =
      typeof evaluatedEvent?.payload["capability"] === "string"
        ? (evaluatedEvent.payload["capability"] as string)
        : undefined;
    const deniedOrHandedOff =
      input.result.terminal?.kind === "denied" || input.result.terminal?.kind === "handoff";

    const cap =
      extras.executedCapability ??
      extras.capabilities[extras.capabilities.length - 1] ??
      (deniedOrHandedOff ? evaluatedCapability : undefined);

    /** 本轮给会话记录用的"标题素材"与台账 ID(在 if 块里赋值,会话记录在块外统一写) */
    let turnFamilyLabel: string | undefined;
    let turnSubject: string | undefined;
    let turnOpId: string | undefined;
    let turnOp: { capability: string; status: OperationStatus; statusLabel: string } | undefined;

    /**
     * ★ 台账只记"真的发生了一件事",不记"只是问了一句"。
     *
     *   三类才落台账:
     *     ① 能力真的执行了(成功或失败);
     *     ② 被策略拦下 / 转人工(被拒绝的请求本身是证据,必须留);
     *     ③ 出了确认卡 / 验证卡(这一刻已经冻结了内容,客户之后要能对上账)。
     *
     *   为什么要排掉"澄清/追问"那一类:它们没有业务结果,却会因为
     *   `extras.capabilities` 里带着意图名而被写成一条「待办理」的记录 ——
     *   于是"问了一句收款人是谁"就把整个会话的状态压回了 pending,
     *   客户在历史列表里看到的是"待办理",而不是"已转账成功"。
     */
    const pendingTierNow =
      input.result.promptFor?.kind === "confirm" || input.result.promptFor?.kind === "strong_auth"
        ? input.result.promptFor.kind
        : undefined;
    const shouldRecordLedger = Boolean(cap) && (executedEvent != null || deniedOrHandedOff || Boolean(pendingTierNow));

    if (cap && shouldRecordLedger) {
      const executedData = executedEvent?.payload["resultData"];
      const outcome = executedEvent
        ? { ok: executedEvent.type === "execution_completed", data: executedData }
        : undefined;

      /**
       * ★ 金额与对象优先取**能力返回值**,确认卡字段只作兜底。
       *
       *   为什么:确认卡只在"待确认"那一轮出现;等客户点了确认,
       *   这一轮的回复里已经没有卡片了 —— 台账若只看卡片,最后落盘的那条
       *   「已转账成功」就会没有金额,历史列表只能显示"转账 · 王秀兰",
       *   客户想核对"那笔多少钱"时反而找不到。
       *   能力返回值是 I3 认定的唯一可信来源,拿它当主口径才是对的。
       */
      const dataRecord =
        executedData != null && typeof executedData === "object"
          ? (executedData as Record<string, unknown>)
          : {};
      const dataNumber = (...keys: string[]): number | undefined => {
        for (const key of keys) {
          const value = dataRecord[key];
          if (typeof value === "number" && Number.isFinite(value)) return value;
        }
        return undefined;
      };
      const dataString = (...keys: string[]): string | undefined => {
        for (const key of keys) {
          const value = dataRecord[key];
          if (typeof value === "string" && value.length > 0) return value;
        }
        return undefined;
      };
      const recordAmount =
        dataNumber("amount", "totalAmount", "estimatedAmount", "refundAmount") ?? amount;
      const recordSubject = subjectField?.value ?? dataString("payeeName", "productName");

      const promptKind = input.result.promptFor?.kind;
      const pendingTier =
        promptKind === "confirm" || promptKind === "strong_auth" ? promptKind : undefined;

      /**
       * ★ 被拦截时给出台账一句话的理由:取**第一条 deny 规则**的说明。
       *   用规则说明而不是整段回复,是因为台账一行放不下,也不该把整段文案抄进数据。
       */
      const denyReason = (input.result.policySummary ?? []).find((r) => r.effect === "deny")?.message;

      const statusInfo = deriveOperationStatus({
        capability: cap,
        ...(outcome ? { outcome } : {}),
        ...(input.result.terminal ? { terminal: input.result.terminal } : {}),
        ...(pendingTier ? { pendingTier } : {}),
        ...(denyReason ? { denyReason } : {}),
        readOnly: Boolean(registry.get(cap)?.readOnly),
      });

      /**
       * ★ 流水号取数优先级(31 文档 §3.3):
       *   reference → applicationId → orderId → transferId。
       *   四者都是"客户可以拿去查这一笔"的编号;不同能力各自用哪个字段,
       *   所以统一在这里收口,免得每个调用点各挑一个。
       */
      const reference = pickOperationReference(executedData);

      // 台账 ID:OP-<traceId 尾 8 位>。固定长度,界面上不会跳来跳去
      const opTail = input.result.traceId.replace(/[^a-zA-Z0-9]/g, "").slice(-8).toUpperCase();
      const opId = opTail.length > 0 ? `OP-${opTail}` : undefined;

      await input.record({
        capability: cap,
        family: flowFamilyOf(cap).label,
        ...(recordAmount != null && Number.isFinite(recordAmount) ? { amount: recordAmount } : {}),
        ...(recordSubject ? { subject: recordSubject } : {}),
        completed: Boolean(extras.executedCapability),
        ...(reference ? { reference } : {}),
        sessionId: input.envelope.sessionId ?? input.envelope.channelUserId,
        status: statusInfo.status,
        statusLabel: statusInfo.label,
        ...(statusInfo.detail ? { detail: statusInfo.detail } : {}),
        ...(opId ? { opId } : {}),
        traceId: input.result.traceId,
        createdAt: nowTs,
      });

      turnFamilyLabel = flowFamilyOf(cap).label;
      turnSubject = recordSubject;
      turnOpId = opId;
      turnOp = { capability: cap, status: statusInfo.status, statusLabel: statusInfo.label };
    }

    /**
     * ★ 提交前取消:把确认卡留下的「待办理」台账行撤掉(第 3 项,与上面"取消不进台账"配套)。
     *   上面刻意不写行只解决了一半 —— 上一轮出确认卡时按规则③已经写了一条 pending,
     *   取消不写结局行的话,那条 pending 会永远悬在客户历史里显示「待办理」,
     *   客户会以为这笔转账还挂着。"什么都没发生"必须连台账一起成立。
     *   证据不丢:取消本身在审计哈希链里(execution_cancelled),台账只是业务视图。
     */
    const cancelledBeforeCommit = [...input.events]
      .reverse()
      .find(
        (e) => e.type === "execution_cancelled" && e.payload["phase"] === "before_commit",
      );
    if (
      cancelledBeforeCommit &&
      typeof cancelledBeforeCommit.payload["capability"] === "string"
    ) {
      await personalization.retractPendingOperation(
        input.envelope.customerId,
        input.envelope.sessionId ?? input.envelope.channelUserId,
        cancelledBeforeCommit.payload["capability"] as string,
      );
    }

    /**
     * ---- 会话记录:每轮原话(脱敏在后端统一做),供历史列表与只读回放 ----
     *
     * ★ 记在**装饰之后**:落盘的是客户实际看到的最终文本(含流程/出处/建议被
     *   精简后的样子),回放才与当时的界面一致。存原始 reply 会回放出一个
     *   客户从没见过的版本。
     */
    const sessionId = input.envelope.sessionId ?? input.envelope.channelUserId;
    // 按钮点击没有文本:用动作翻出一句人话,避免回放里出现空消息
    const userTurnText = input.envelope.action
      ? actionLabelForReplay(input.envelope.action)
      : input.envelope.text;
    if (userTurnText.trim().length > 0) {
      await sessions.appendTurn(input.envelope.customerId, {
        sessionId,
        channel: input.envelope.channel,
        ts: nowTs,
        role: "user",
        text: userTurnText,
        traceId: input.result.traceId,
      });
    }
    await sessions.appendTurn(input.envelope.customerId, {
      sessionId,
      channel: input.envelope.channel,
      ts: nowTs,
      role: "agent",
      text: decoration.reply,
      traceId: input.result.traceId,
      promptKind: input.result.promptFor?.kind ?? "none",
      ...(input.result.card?.title ? { cardTitle: input.result.card.title } : {}),
    });

    // 会话级状态:由"每个能力的最新状态"聚合(同一能力只认最新一条,再比优先级)
    await sessions.upsertSession(
      input.envelope.customerId,
      {
        sessionId,
        channel: input.envelope.channel,
        startedAt: nowTs,
        lastAt: nowTs,
        ...(turnFamilyLabel ? { title: `${turnFamilyLabel}${turnSubject ? ` · ${turnSubject}` : ""}` } : {}),
        ...(turnOpId ? { operationIds: [turnOpId] } : {}),
        ...(turnOp ? { op: { ...turnOp, at: nowTs } } : {}),
      },
      nowTs,
    );

    /**
     * ---- 常用流程:**不再自动保存** ----
     *
     * ★ 上一版是"办成一件事就自动记住",结果是常用服务里堆了一串客户没选过的条目。
     *   客户的原话是:"不要举例那么多,搞一两个我用过有次数在那就好,
     *   以后有新增的是我说添加到常用流程再添加的。"
     *
     *   所以现在的规则很直接:
     *     · 只有**客户明确要求**(点「存为常用流程」按钮,或说"把刚才那个存成常用流程")
     *       才会落盘;
     *     · 系统**绝不**替客户决定什么算他的常用业务。
     *   这不是省事,而是"常用"这个词的定义权属于客户 ——
     *   系统自己塞进去的,对客户来说只是噪音。
     *
     *   落盘入口因此只有一个:`saveRecentFlow`(由编排器在收到明确指令时调用)
     *   与 `/api/flows/save`(按钮)。两者共用 deriveFlowFromEvents,派生结果一致。
     */

    // ---- 审计留痕:客户实际看到的最终文本 ----
    await audit.append({
      ts: nowTs,
      traceId: input.result.traceId,
      sessionId: input.envelope.sessionId ?? input.envelope.channelUserId,
      customerId: input.envelope.customerId,
      channel: input.envelope.channel,
      type: "response_decorated",
      payload: {
        ok: true,
        flowKey: decoration.flow?.flowKey ?? null,
        flowSteps: decoration.flow?.steps.length ?? 0,
        handedToHuman: decoration.flow?.handedToHuman ?? false,
        citations: decoration.citations.map((c) => ({ id: c.id, topic: c.topic, source: c.source, effective: c.effective })),
        suggestions: decoration.suggestions.map((s) => ({ id: s.id, ruleId: s.ruleId, reason: s.reason })),
        /** 被精简层删掉的句子 —— "给客户看的是精简版"这件事必须可复核 */
        removedLines: decoration.removedLines,
        finalText: decoration.reply,
        note:
          "response_sent 记录的是业务主回复;这里记录客户**实际看到的最终文本**" +
          "(含办理流程、来源标注、主动建议)。两者不同时必须能查到差异。",
      },
    });

    return {
      ...input.result,
      reply: decoration.reply,
      ...(decoration.flow ? { flow: decoration.flow } : {}),
      ...(decoration.citations.length > 0 ? { citations: decoration.citations } : {}),
      ...(decoration.suggestions.length > 0 ? { suggestions: decoration.suggestions } : {}),
      ...(decoration.visual ? { visual: decoration.visual } : {}),
    };
  };

  // ---- 编排器 ----
  const orchestrator = new AgentOrchestrator({
    bank,
    audit,
    registry,
    intentParser,
    getProfile: async (customerId) => buildProfile(customerId, world),
    getChannelCapabilities: (channel) => CHANNEL_CAPABILITIES[channel],
    // ★ 可选依赖最容易漏传(交接 §10 坑 #2):retrieval 忘了注入,
    //   policy.search 就会静默变成"检索未就绪"。这里显式带上。
    ...(retrieval ? { retrieval } : {}),
    verifyAuthProof,
    // ★ 签发方是"外部安全环境",不是 Agent —— 以依赖注入的形式明确这层边界。
    //   演示环境用 HMAC 模拟;生产环境应为 HSM 内的非对称签名。
    issueAuthProof: async (input) =>
      signAuthProof({
        method: input.method,
        boundPayloadHash: input.boundPayloadHash,
        now: input.now,
        ttlMs: input.ttlMs,
      }),
    now,
    // ---- 交互体验层(流程可视化 / 来源标注 / 主动建议 / 常用流程) ----
    turnDecorator,
    suggestionPort: suggestionEngine,
    suggestionFacts: (i) => buildFacts(i.customerId, i.now),
    savedFlows: async (customerId) =>
      (await personalization.listFlows(customerId)).map((f) => ({
        templateId: f.templateId,
        name: f.name,
        capability: f.capability,
        sentence: f.sentence,
      })),
    instantiateFlow: (templateId, customerId) => personalization.instantiate(customerId, templateId),
    noteFlowUsed: (templateId, customerId) => personalization.touchFlow(customerId, templateId, now()),
    /** ★ 客户说"把刚才那个存成常用流程"时走这里(唯一的人工保存入口之一) */
    saveRecentFlow: (input) => saveRecentFlow(input),
    recordHistory: async (entry) => {
      await personalization.recordHistory(entry.customerId, {
        ts: entry.ts,
        capability: entry.capability,
        family: entry.family,
        ...(entry.amount != null ? { amount: entry.amount } : {}),
        ...(entry.subject ? { subject: entry.subject } : {}),
        completed: entry.completed,
        ...(entry.reference ? { reference: entry.reference } : {}),
        // ---- 台账字段(缺哪个就不写哪个,保持旧文件可读) ----
        ...(entry.sessionId ? { sessionId: entry.sessionId } : {}),
        ...(entry.status ? { status: entry.status } : {}),
        ...(entry.statusLabel ? { statusLabel: entry.statusLabel } : {}),
        ...(entry.detail ? { detail: entry.detail } : {}),
        ...(entry.opId ? { opId: entry.opId } : {}),
        ...(entry.traceId ? { traceId: entry.traceId } : {}),
        ...(entry.createdAt != null ? { createdAt: entry.createdAt } : {}),
      });
    },
  });

  /**
   * ---- 演示登录凭据 ----
   *
   * ★ 如实说明这套凭据的性质,不含糊:
   *   银行核心(mock)里**没有**客户凭据这个概念 —— 那是对的,凭据不该由业务数据存。
   *   所以演示环境的登录口令来自**环境变量**(`AUTH_DEMO_PASSWORD`,可给单个客户
   *   用 `AUTH_DEMO_PASSWORD_PRIMARY` / `AUTH_DEMO_PASSWORD_SPOUSE` 覆盖),
   *   默认值是下面这个公开的演示口令。
   *
   *   这意味着:**演示环境的"登录"证明的是"你知道演示口令",不是"你是这位客户"**。
   *   它真正的价值在于把架构补完整 —— 身份由服务端签发、请求体里的 customerId
   *   不再被采信、越权尝试落审计链。生产环境必须换成真实的凭据校验
   *   (短信/密码器/生物识别 + 客户凭据库),这一点在 README 与自评报告里写明。
   */
  const demoPassword = env["AUTH_DEMO_PASSWORD"] ?? DEMO_DEFAULT_PASSWORD;

  async function verifyCredential(customerId: string, password: string): Promise<CredentialVerdict> {
    const known: Array<{ id: string; name: string; password: string }> = [
      { id: world.primaryCustomerId, name: "张先生", password: env["AUTH_DEMO_PASSWORD_PRIMARY"] ?? demoPassword },
      { id: world.spouseCustomerId, name: "赵女士", password: env["AUTH_DEMO_PASSWORD_SPOUSE"] ?? demoPassword },
    ];
    const found = known.find((k) => k.id === customerId);

    /**
     * ★ 无论客户号是否存在,都做一次**等时**的比较。
     *
     *   若"客户不存在就直接返回",响应时间的差异本身就是一个账号探测信道
     *   (0.1ms vs 2ms 用统计方法完全能分辨)。这里的做法是:
     *   拿默认口令当"陪跑值"比一次,再根据 found 决定结论。
     */
    const expected = found?.password ?? demoPassword;
    const given = Buffer.from(password, "utf8");
    const want = Buffer.from(expected, "utf8");
    const same = given.length === want.length && timingSafeEqual(given, want);

    if (!found) return { ok: false, reason: "unknown_customer" };
    if (!same) return { ok: false, reason: "bad_password" };
    return { ok: true, reason: "ok", kind: "demo_password", displayName: found.name };
  }

  return {
    orchestrator,
    world,
    bank,
    audit,
    llm,
    personalization,
    sessions,
    auth,
    now,
    verifyCredential,
    /** 制度检索索引(评测脚本与调试用;可能为 null —— 语料缺失时) */
    policyIndex,
    wealthProfile: (customerId: string) => bank.getRiskProfile(customerId),
    envelope(input) {
      return {
        channel: input.channel,
        channelUserId: input.channelUserId ?? `ch_${input.channel}_001`,
        customerId: input.customerId ?? world.primaryCustomerId,
        text: input.text,
        /**
         * ★ 允许调用方带上 messageId。
         *
         * 为什么必须能带:幂等键就是由 messageId 派生的(`idem_<messageId>`)。
         * 过去这里每调用一次就随机一个新 messageId —— 于是**同一个请求重放**
         * 也永远是一个新的幂等键,幂等保护在结构上就不可能生效。
         * 真实的银行渠道(短信/网银回调)本来就会带业务流水号,调用方带着它重试
         * 才是幂等要挡的场景;不带时才由服务端生成。
         */
        messageId: input.messageId ?? `msg_${randomUUID().slice(0, 16)}`,
        // ★ 中止意图原样带上(第 3 项):它只是随请求进来的数据快照,
        //   真正决定"提不提交"的是银行核心的提交边界(app.envelope 不做判断)
        ...(input.cancellation ? { cancellation: input.cancellation } : {}),
        sessionId: input.sessionId ?? `sess_${input.channel}_demo`,
        ts: now(),
      };
    },
    // ---- 常用流程(真实落盘:进程重启后仍在) ----
    listFlows: (customerId) => personalization.listFlows(customerId),
    saveFlow: (customerId, template) => personalization.saveFlow(customerId, template),
    removeFlow: (customerId, templateId) => personalization.removeFlow(customerId, templateId),
    instantiateFlow: (customerId, templateId) => personalization.instantiate(customerId, templateId),
    deriveFlowForTrace: (input) => deriveFlowFromAudit(input),
    saveRecentFlow: (input) => saveRecentFlow(input),
    /**
     * 首页个性化视图。
     *
     * ★ 这里把"常用流程"与"智能建议"合成一个视图,因为它们最终都渲染在
     *   App 首页的同一块区域(常用服务)。分开两次请求会让界面出现
     *   "先显示常用流程、过一会儿又冒出一条建议"的抖动。
     */
    async personalizationView(customerId: string, sessionId?: string) {
      const nowTs = now();
      const flows = await personalization.listFlows(customerId);
      const facts = await buildFacts(customerId, nowTs);
      const suggestions = await suggestionEngine.suggest(facts);
      const allowed = await personalization.filterSuggestions(customerId, suggestions, nowTs);
      const [subscriptions, holdings, products, schedules, risk] = await Promise.all([
        bank.listSubscriptions(customerId),
        bank.listWealthHoldings(customerId),
        bank.listWealthProducts({}),
        bank.listSchedules(customerId),
        bank.getRiskProfile(customerId),
      ]);
      const desk = buildCustomerDesk({
        now: nowTs,
        pending: orchestrator.pending.listFor(customerId, nowTs),
        subscriptions,
        holdings,
        products,
        schedules,
        plan: sessionId ? orchestrator.liveEventPlan(sessionId, nowTs) : null,
        risk,
        suggestions: allowed,
        billHealth: facts.billHealth ?? null,
        idleCash: facts.idleCash ?? null,
      });
      return {
        flows: flows.map((f) => {
          const say = templateToSay(f);
          return { ...f, say };
        }),
        history: (await personalization.history(customerId)).slice(-20).reverse(),
        suggestions: allowed.map((s) => ({ ...s, say: s.say })),
        desk,
      };
    },
  };
}
