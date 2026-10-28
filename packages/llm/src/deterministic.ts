/**
 * 离线确定性解析器(Deterministic Provider)
 *
 * 用途:在无 API Key、断网、或演示现场翻车时,**不调用任何外部服务**,
 *      用规则引擎完成意图解析,保证整条链路(意图 → 计划 → 裁决 → 确认 → 执行 → 审计)
 *      依然完整可演示。
 *
 * 定位说明(会写进答辩材料):
 *   这不是"功能阉割版"。它本身就是一套有价值的能力 ——
 *   ① 高频简单指令用规则解析比调用模型更快、更省、更稳定;
 *   ② 它同时是**校验基线**:当模型输出与规则输出严重不一致时触发复核;
 *   ③ 它是可演示性的最后一道保险。
 *
 * 局限:规则解析器不擅长模糊表达与隐含意图,这正是需要大模型的地方。
 *      因此它只覆盖高频明确指令,遇到复杂表达会显式返回低置信度并要求澄清。
 */

import {
  isSystemInjectedMessage,
  type LlmCompletionRequest,
  type LlmCompletionResult,
  type LlmProvider,
  type LlmToolCall,
} from "./provider.ts";
import type { Intent, ParsedRequest } from "../../core/src/intent/schema.ts";
import { extractOrdinalRefs } from "../../core/src/agent/ordinal.ts";
import { isEventReleaseSpoken, isOrderedStepExecutionSpoken } from "../../core/src/intent/eventWording.ts";




export class DeterministicProvider implements LlmProvider {
  readonly name = "deterministic";
  readonly model = "rule-based-v1";

  async complete(request: LlmCompletionRequest): Promise<LlmCompletionResult> {
    const started = Date.now();

    // 找到最后一条**真实用户**消息作为解析输入(跳过系统注入的重试提示语)
    const lastUser = [...request.messages]
      .reverse()
      .find((m) => m.role === "user" && !isSystemInjectedMessage(m.content));
    const text = lastUser?.content ?? "";

    // 若请求要求工具调用,则以工具调用形式返回(与真实模型同构)
    if (request.tools && request.tools.length > 0) {
      const parsed = parseWithRules(text);
      const tool = request.tools[0]!;
      const toolCall: LlmToolCall = {
        id: `call_${Date.now().toString(36)}`,
        name: typeof request.toolChoice === "object" ? request.toolChoice.name : tool.name,
        arguments: JSON.stringify(parsed),
      };
      return {
        content: "",
        toolCalls: [toolCall],
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
        model: this.model,
        finishReason: "tool_calls",
        latencyMs: Date.now() - started,
      };
    }

    // 否则返回 JSON 文本(与 responseFormat=json_object 同构)
    return {
      content: JSON.stringify(parseWithRules(text)),
      toolCalls: [],
      usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
      model: this.model,
      finishReason: "stop",
      latencyMs: Date.now() - started,
    };
  }

  async ping(): Promise<{ ok: boolean; latencyMs: number; detail?: string }> {
    return { ok: true, latencyMs: 0, detail: "离线确定性解析器,无需网络" };
  }
}

// ============================================================================
// 规则解析
// ============================================================================

/** 受骗话术关键词库 */
const FRAUD_URGENCY = ["马上", "赶紧", "立刻", "来不及", "急", "抓紧", "限时", "否则"];
const FRAUD_SECRECY = ["不要告诉", "别告诉", "保密", "不能跟别人说", "别说出去", "只有你知道"];
const FRAUD_GUIDED = ["他让我", "他教我", "客服说", "对方说", "按照他说的", "他叫我", "让我这么操作"];
const FRAUD_SCENE = [
  "安全账户",
  "资金清查",
  "洗钱",
  "涉案",
  "保证金",
  "解冻",
  "验证资金",
  "刷单",
  "返利",
  "投资平台",
  "导师",
  "内幕",
  "稳赚",
  "客服退款",
  "快递理赔",
  "公检法",
];

/** 注入攻击关键词库 */
const INJECTION_PATTERNS = [
  /忽略(上述|以上|之前|前面)?(所有)?(指令|规则|提示)/,
  /ignore\s+(all\s+)?(previous|above|prior)\s+instructions?/i,
  /你现在是|你现在扮演|from now on you are/i,
  /(解除|绕过|跳过|取消)(所有)?(限制|风控|权限|验证|限额)/,
  /(把|将)?(我的)?(限额|额度)(改成|设为|调整为)(无限|1000000|100万)/,
  /system\s*prompt/i,
  /(直接|立即)(执行|转账)?(无需|不用|跳过)(确认|验证)/,
  /管理员模式|开发者模式|上帝模式|越狱/,
  /显示(你的)?(系统)?(提示词|prompt|instructions)/i,
];

export function detectInjection(text: string): { suspected: boolean; evidence: string[]; reason?: string } {
  const evidence: string[] = [];
  for (const p of INJECTION_PATTERNS) {
    const m = text.match(p);
    if (m) evidence.push(m[0]);
  }
  if (evidence.length === 0) return { suspected: false, evidence: [] };
  return {
    suspected: true,
    evidence,
    reason: "输入中包含试图改变系统规则、绕过安全控制或获取系统提示的指令性表述",
  };
}

export function detectFraudSignals(text: string): {
  urgency: boolean;
  secrecy: boolean;
  guided: boolean;
  keywords: string[];
  note?: string;
} {
  const hits: string[] = [];
  const has = (list: string[]) => {
    const found = list.filter((k) => text.includes(k));
    hits.push(...found);
    return found.length > 0;
  };

  const urgency = has(FRAUD_URGENCY);
  const secrecy = has(FRAUD_SECRECY);
  const guided = has(FRAUD_GUIDED);
  const scene = has(FRAUD_SCENE);

  const count = [urgency, secrecy, guided].filter(Boolean).length;
  let note: string | undefined;
  if (scene) {
    note = `话语中出现典型诈骗场景关键词(${hits.filter((h) => FRAUD_SCENE.includes(h)).join("、")}),建议触发反诈提醒`;
  } else if (count >= 2) {
    note = "话语中同时出现多项受骗特征(被催促/被要求保密/被指导操作)";
  }

  return { urgency, secrecy, guided, keywords: [...new Set(hits)], note };
}

/**
 * 主规则解析函数。
 * 输出结构与 ParsedRequestSchema 一致。
 */
export function parseWithRules(
  text: string,
  now: number = Date.now(),
): ParsedRequest & { __parser: string } {
  const t = text.trim();
  const fraudSignals = detectFraudSignals(t);
  const injectionSuspicion = detectInjection(t);

  const intent = parseIntent(t, now);
  const multiIntent = splitMultiIntent(t, now);

  const base = {
    intent,
    ...(multiIntent ? { multiIntent } : {}),
    fraudSignals,
    injectionSuspicion,
    __parser: "deterministic-rules-v1",
  };
  return base as ParsedRequest & { __parser: string };
}

/**
 * 确定性多意图拆分(离线路径)。
 *
 * ★ 为什么离线路径也必须支持:大模型路径能把
 *   「先给老妈转2000,再给房东转5800」拆成两步,离线规则路径以前只会回一句
 *   "请分开说"。而离线模式是**现场网络不可控时的兜底**,也是队友/评委最容易
 *   跑起来的那条路 —— 能力不该因为换了个解析器就消失。
 *
 * 策略刻意保守:
 *   ① 只有出现明确顺序连接词(先/再/然后/接着/最后/;)才尝试拆分;
 *   ② 每个分句必须能独立成一个"可执行动作",否则丢弃该分句;
 *   ③ 少于 2 个有效分句 → 不产出 multiIntent(交给上层提示用户分开说)。
 */
function splitMultiIntent(text: string, now: number): ParsedRequest["multiIntent"] {
  const hasSequence = /(先|首先|再|然后|接着|之后|最后|还要|顺便|另外)/.test(text) || /[;；]/.test(text);
  if (!hasSequence) return undefined;

  const clauses = text
    .split(/(?:[;；])|(?:[,，]?\s*(?:先|首先|再|然后|接着|之后|最后|还要|顺便|另外)\s*)/)
    .map((s) => s.replace(/^[,，。;；\s]+/, "").trim())
    .filter((s) => s.length >= 3);

  if (clauses.length < 2) return undefined;

  const items: Array<{ capability: string; label: string; input: Record<string, unknown>; moneyMovement: boolean }> = [];
  for (const clause of clauses) {
    const mapped = mapIntentToPlanItem(parseIntent(clause, now));
    if (!mapped) continue;
    items.push(mapped);
  }

  if (items.length < 2) return undefined;

  return {
    restatedIntent: `用户想按顺序做 ${items.length} 件事:${items.map((i) => i.label).join(";")}`,
    items,
  };
}

/** 把单个子意图映射为计划项(能力名 + 入参)。无法独立成事时返回 null。 */
function mapIntentToPlanItem(intent: Intent): {
  capability: string;
  label: string;
  input: Record<string, unknown>;
  moneyMovement: boolean;
} | null {
  const payeeName = intent.payee?.name ?? intent.payee?.alias ?? intent.payee?.raw;
  const amount = intent.amount?.value;

  if (intent.action === "transfer.send" || intent.action === "transfer.schedule") {
    if (!payeeName || !amount) return null;
    const isSchedule = intent.action === "transfer.schedule";
    return {
      capability: isSchedule ? "transfer.create_schedule" : "transfer.submit",
      label: `${isSchedule ? "设置定时转账:" : ""}给「${payeeName}」转 ${amount} 元${intent.memo ? `,备注「${intent.memo}」` : ""}`,
      input: {
        fromAccountId: "default",
        payeeName,
        amount,
        currency: "CNY",
        ...(intent.memo ? { memo: intent.memo } : {}),
      },
      moneyMovement: true,
    };
  }

  if (intent.action === "collection.create") {
    const col = intent.collection;
    if (!col || (col.participants?.length ?? 0) < 2 || col.totalAmount.value <= 0) return null;
    return {
      capability: "collection.create",
      label: `发起 AA 收款「${col.title}」共 ${col.totalAmount.value} 元`,
      input: {
        title: col.title,
        totalAmount: col.totalAmount.value,
        currency: col.totalAmount.currency,
        splitMode: col.splitMode,
        participants: col.participants.map((p) => ({ displayName: p.displayName })),
        feeBearer: col.feeBearer,
        allowPartial: col.allowPartial,
      },
      moneyMovement: false,
    };
  }

  // 只读查询可以安全地放进计划
  if (intent.action === "account.balance") {
    return { capability: "account.list_balances", label: "查询账户余额", input: {}, moneyMovement: false };
  }
  if (intent.action === "account.analysis") {
    return { capability: "account.analyze_spending", label: "统计消费情况", input: {}, moneyMovement: false };
  }
  if (intent.action === "account.transactions") {
    return { capability: "account.list_transactions", label: "查询交易流水", input: {}, moneyMovement: false };
  }

  // ---- 理财(场景三)----
  // ★ 只把**只读**理财动作放进多步计划。
  //   申购与赎回涉及资金,必须单独成事、单独确认 ——
  //   把它们塞进一个多步计划里,用户点一次"确认"就会连带执行,
  //   那就等于"一次确认授权了多笔资金操作",与 I5(每个副作用节点独立裁决)冲突。
  if (intent.action === "wealth.list_products") {
    return {
      capability: "wealth.list_products",
      label: intent.amount ? `按约 ${intent.amount.value} 元预算挑选理财产品` : "查询理财产品",
      input: {
        ...(intent.wealth?.riskPreference ? { maxRiskLevel: intent.wealth.riskPreference } : {}),
        ...(intent.wealth?.typePreference ? { type: intent.wealth.typePreference } : {}),
      },
      moneyMovement: false,
    };
  }
  if (intent.action === "wealth.holdings") {
    return { capability: "wealth.holdings", label: "查询理财持仓与收益", input: {}, moneyMovement: false };
  }
  if (intent.action === "wealth.risk_assess") {
    return { capability: "wealth.risk_assess", label: "进行风险承受能力测评", input: {}, moneyMovement: false };
  }

  return null;
}

function parseIntent(text: string, now: number): Intent {
  const amount = extractAmount(text);
  const payee = extractPayee(text);
  const memo = extractMemo(text);
  const schedule = extractSchedule(text, now);
  const fromAccount = extractFromAccount(text);

  const missing: Intent["missingSlots"] = [];
  if (!payee) missing.push("payee");
  if (!amount) missing.push("amount");

  // ---- 动作判定(顺序即优先级) ----
  // ★ 隐含 AA 识别:「这顿饭600,我和李明、王秀兰一起吃的」
  //   用户完全没提"AA",但从"多人 + 总额 + 一起/共同"就能推断出共担意图。
  //   这是真实的隐含意图:用户脑子里想的是"帮我跟他们要回来",
  //   而字面上没有任何一个"分摊"的词。
  const namesInText = (text.match(/[\u4e00-\u9fa5]{2,4}(?:[、,和及][\u4e00-\u9fa5]{2,4})+/g) ?? []).length;
  const sharedCue = /(一起|共同|大家|我们|几个人|拼的|平摊|一人一半|均摊)/.test(text);
  const implicitCollection = namesInText >= 1 && sharedCue;
  const isCollection = /(AA|aa|分摊|拼单|收款|让大家还|一起凑|均摊)/.test(text) || implicitCollection;

  // ---- 取消类:必须先区分"取消计划"与"撤销已转出的钱" ----
  // ★ 踩过的坑:用户说「取消定时转账」,早期只判断 /(撤销|撤回|取消那笔|退回)/,
  //   "取消定时转账"不含"取消那笔",于是 isCancel=false;
  //   接着 isSchedule 命中"定时" → 被判成"创建定时转账" → 系统追问"要转多少钱"。
  //   用户只是想停掉一个计划,却被告知"请问要转多少钱" —— 完全的答非所问。
  const cancelVerb = /(取消|终止|停止|停掉|关掉|关闭|不要了|别再|不想再|撤了)/.test(text);
  const scheduleWord = /(定时|周期|自动转|定期|每月|每周|计划|预约)/.test(text);
  const isCancelSchedule = cancelVerb && scheduleWord;

  // 撤销一笔已经转出去的钱(涉及资金退回)
  const isCancel =
    !isCancelSchedule && /(撤销|撤回|退回|取消那笔|取消刚才|取消上一笔|把那笔.*(取消|撤销)|转错)/.test(text);
  const isSchedule = !isCancelSchedule && /(每月|每周|每天|定时|自动转|定期转|下个月|固定)/.test(text);
  const isSecurity = /(手机号|密码|换绑|改绑)/.test(text) && /(改|换|重置|修改)/.test(text);

  // ---- AA 收款状态查询 / 催收 ----
  // ★ 踩过的坑:用户发起 AA 后问「他们付钱了吗」,早期无法识别 ——
  //   它既不含"AA/分摊/收款",也不含"多少钱/流水/账单",
  //   于是掉进转账分支被追问金额。
  //   这类问法在真实对话里极常见(垫付之后总会想知道钱回来没有)。
  const isCollectionStatus =
    /(他们|大家|其他人|参与人|那几个人|别人)/.test(text) && /(付|给|还|转).{0,3}(钱|款|了)/.test(text)
    || /(收齐|收上来|收回来|回款|到账了没|谁还没付|谁没付|催一下|催收|进度|还差谁|都付了吗|付了没有)/.test(text)
    || (/AA|分摊|收款/.test(text) && /(进度|状态|怎么样|如何|付了|还了|收齐|明细)/.test(text));

  // ★ 记账意图:「帮我记一下」「这笔是借他的」「记成房租」
  //   注意与"查询流水"区分:记账是**写入**一个新批注,不是查已有记录。
  const isNote = /(帮我记|记一下|记一笔|记成|记作|备注一下|标记一下|记账)/.test(text)
    || (/(这笔|这钱|这个钱)/.test(text) && /(是|算)/.test(text) && /(借|还|报销|房租|货款|押金|定金)/.test(text));

  // ★ "花了多少"是**分析**,"流水/明细"是**罗列** —— 两者必须区分开。
  //   用户问"我这个月餐饮花了多少",要的是分类汇总的金额,不是一串交易记录。
  //   返回一串流水既答非所问,又让用户自己去加总,是典型的"看似成功实则失败"。
  const isAnalysis = /(花了多少|花了好多|花了多少|一共花|总共花|总支出|支出多少|花了多少钱|占比|统计|分析|对比|趋势|哪方面|主要花|消费结构|是不是花|是否花|花太多|花得多|怎么这么|为什么这么|花了这么多|正常吗|合理吗|比以前|比上月|环比)/.test(
    text,
  );
  const isList = /(流水|明细|记录|清单|列表|查一下.*交易|最近.*交易)/.test(text);

  // ---- 理财场景(场景三)的意图识别 ----
  // ★ 设计时就预判到的坑:"我有5万块,推荐几个理财产品"这句话里
  //   既有金额(5万)又有"推荐"。如果只按金额走,它会掉进转账分支,
  //   系统会问"这笔钱要转给谁" —— 用户想买理财,却被问转给谁。
  //   因此理财识别必须**早于**转账兜底,且以"理财语义词"为硬触发条件,
  //   绝不能只看"有金额"就判定。
  //
  // ★ 线索词覆盖面是实测调出来的。曾经漏掉的真实说法:
  //   「介绍下纯债添利B」「这个产品起购多少」「稳健增利多久能到账」
  //   「赎回要多久到账」「这两个哪个风险低」「把科技成长精选全赎了」
  //   这些都是很自然的人话,漏了就会被当成转账去追问收款人。
  const wealthCue =
    /(理财|理财产品|基金|净值|申购|赎回|持仓|收益率|年化|货币|债券|纯债|债基|固收|混合|股票型|指数|存单|定期存款|风险等级|风险测评|风险承受|稳健型|保守型|进取型|起购|到账|买入|建仓|R[1-5]|C[1-5])/.test(
      text,
    );
  // ★ 「介绍下纯债添利B」这类说法:整句里唯一的理财信号就是产品名本身。
  //   而产品名只有停用词表之外的词才安全 —— 这里用"产品名后接档位字母/数字"
  //   这种强特征来识别,避免把「介绍下张三」也当成理财。
  const wealthProductMention = /[\u4e00-\u9fa5]{2,8}[A-Za-z]?\d?(?=\s|$)/.test(text) && /(介绍|详情|说说|是什么)/.test(text);
  const wealthLookup =
    /(产品|理财|基金|标的)/.test(text) && /(推荐|几个|哪些|有什么|看看|介绍|找一?找|选)/.test(text);
  const isProductList =
    (wealthCue || wealthLookup) &&
    /(推荐|几个|哪些|有什么|有没有|看看|介绍|列表|选|买什么|怎么选|排行|收益高)/.test(text) &&
    !/(赎回|卖出|取出来|转出|对比|比较)/.test(text);
  // ★ "对比意图"要先于"购买意图"判断:「纯债添利和平衡配置哪个好」里有"买"吗?
  //   没有,但有"哪个好"。而「这个产品要买多少起」里有"买"却不是对比。
  //   两类句式高度相似,靠"是否出现对比词"区分最稳。
  //
  // ★ 但判据本身必须**排除子串误命中**(实测踩到):
  //   「第1个的详情」里的"第1个的"含子串「哪个」,于是它被判成了**对比**意图,
  //   再往后又因为"第"字被当成收款人而掉进转账分支。
  //   修法有两层:① 对比词要求是完整词,不能用会被包含进去的短片段;
  //              ② 明确说了"详情/介绍/是什么"的,详情意图优先。
  const isDetailCue = /(详情|详细|具体情况|介绍一下|介绍下|说说|是什么|什么情况|起购|门槛|费率|管理费|多久|多长时间|几天|到期|期限|怎么样)/.test(
    text,
  );
  const isWealthCompareCue =
    !isDetailCue &&
    /(哪个好|哪个更|哪个划算|哪个收益|哪个高|哪个低|哪个风险|哪个稳|哪只更好|对比|比较|相比|区别|vs|VS)/.test(text);
  const isCompare =
    (isWealthCompareCue && (wealthCue || /(这个|那个|两只|两个|这俩)/.test(text) || /比/.test(text))) ||
    // 「这两个哪个风险低」这类没有产品或基金字样的口语对比
    (/(这|那)(个|只|两|几)/.test(text) && /(哪个|对比|比较|区别)/.test(text)) ||
    // ★ 「第1个和第3个对比一下」——有位置指代 + 对比动作
    (text.includes("第") && /(对比|比较|比一下|比一比|哪个|区别)/.test(text));
  const isDetail =
    (wealthCue || wealthProductMention) &&
    /(详情|详细|具体情况|是什么|什么情况|介绍一下|介绍下|说说|起购|门槛|费率|管理费|多久|多长时间|几天|到期|期限|什么时候到账|随时赎回|什么时候能到)/.test(
      text,
    ) &&
    !isCompare;
  const isAssessment =
    /(风险测评|风险承受|风险等级|承受能力|测评|评估|能不能买|可以买|适合我|买得了)/.test(text) &&
    /(测评|风险承受|风险等级|承受能力|评估|能不能买|可以买|适合我|买得了|股票型|高风险|做一下|重新做)/.test(
      text,
    );
  const isPurchase =
    !isWealthCompareCue &&
    /(申购|买入|买点|买一?个|买些|购买|入手|配置|投点|投一?点|买[0-9零一二两三四五六七八九十百千万]+|建仓|想买|要买)/.test(
      text,
    ) && !/(赎回|卖出|取出来|转出)/.test(text);
  const isRedeem = /(赎回|卖出|卖掉|赎了|全赎|清仓|平仓|取出来|变现|退出|全部赎回|撤出|提出来)/.test(text);
  const isHolding =
    /(持仓|我持有的|我买的|持有的|赚了多少|亏了多少|收益怎么样|现在值多少|市值|我的理财|买的理财|理财怎么样)/.test(
      text,
    ) && !/(推荐|哪些产品|有什么产品)/.test(text);
  const isSignConsent = /(签确认书|签署确认书|风险确认书|不匹配确认书|签一下确认书|我签|同意承担风险|确认承担风险)/.test(
    text,
  );
  // ★ 兜底:说了"买"类动词 + 泛指产品词但没具体动作 —— 「买理财」「买点理财」
  const isVagueWealth =
    /(买|申购|投|配置)/.test(text) && /(理财|基金|产品|标的)/.test(text) && !/(赎|卖|取)/.test(text);

  // ★ 兜底二:位置指代 + 对比/查看动作 —— 「第1个和第3个对比一下」「1和3比一下」
  //
  //   这类句子里**一个理财语义词都没有**:没有"理财""基金""产品",
  //   只有序号和一个"比"字。之前的判据全靠 wealthCue 起头,于是它
  //   掉进了转账分支 —— 用户说"1和3比一下",系统回"这笔要转多少钱"。
  //
  //   判据必须有,但不能太宽:仅当"抽到了位置指代"且"句子里有对比或查看动作"时成立。
  //   「1和3」这样一串数字本身不构成理财意图(它更可能是别的东西),
  //   加上"比一下/对比/哪个/怎么样"才构成。
  const ordinalRefsProbe = extractOrdinalRefs(text);
  const isOrdinalWealth =
    ordinalRefsProbe.length > 0 &&
    /(对比|比较|比一下|比一比|哪个|区别|怎么样|如何|详情|介绍)/.test(text);

  // ★ 一键申购/赎回:「买第4个5万」「申购第2个」「卖第2个」「赎回第1个」
  //
  //   这是"列表 → 直接下单"这条最短路径。用户在列表里看到编号,
  //   最自然的说法就是"买第几个 + 金额"。旧判据完全不覆盖:
  //   它既没有"理财/基金/产品"等语义词,也不是"对比/详情",
  //   于是「买第4个5万」被当成"转给一个叫『买第』的人"。
  //
  //   判据要点:动词(买/申购/卖/赎回)+ 位置指代,两者缺一不可 ——
  //   单独一个"买"或单独一个"第4个"都不构成下单意图。
  const isBuyOrdinal =
    /(买|申购|购买|入手|投|配置|下单|建仓)\s*第/.test(text) && ordinalRefsProbe.length > 0;
  const isRedeemOrdinal =
    /(赎回|卖出|卖掉|卖|赎|清仓|全赎|取出来|提出来|撤出)\s*第/.test(text) && ordinalRefsProbe.length > 0;

  // ---- 卡片管理场景(场景四)的意图识别 ----
  //
  // ★ 为什么必须排在理财之前:「信用卡」里含「信用」两个字不冲突,
  //   但「额度」这个词两边都会用 —— 理财没有"额度",可它出现在
  //   「这个产品有没有额度要求」这种问法里。真正的歧义点在于:
  //   卡片的动作词(挂失/补卡/激活/解限/提额)在理财里一个都不会出现,
  //   因此判据用**卡片专属动作词**做硬触发,而不是靠"额度"这种共用词。
  //
  // ★ 实测最容易漏的说法(每一条都必须能接住):
  //   「信用卡额度太低能不能提额」「卡被限制了帮我解开」「想办一张新卡」
  //   「卡丢了先挂失」「挂失后补办要多久能不能保留原卡号」「新卡到了怎么激活」
  //   ★ 一个真实踩到的坑(踩了两次,同一类):最短也最常见的那几句反而漏了 ——
  //     · 「我有哪些卡?」:与卡有关的字只有句尾那个"卡";
  //     · 「卡丢了」「我卡丢了」:同样只有那个"卡"。
  //     早期判据是一长串具体说法(信用卡/银行卡/我的卡/…),
  //     于是"卡"单独出现时判不出来 —— 而它恰恰是**最紧急**的那一句。
  //     教训:枚举说法永远盖不全,关键的单字必须有兜底。
  //
  //   ★ 但兜底不能放宽成"含『卡』就算卡片场景":实测「给老妈转500,
  //     卡里钱不够的话先别转」里也有"卡",一旦放宽它会被当成查卡片列表,
  //     而这句明明是一笔转账。因此兜底写成**卡 + 卡片专属动作**的组合,
  //     而不是裸露的一个"卡"字。
  const cardCue =
    /(信用卡|贷记卡|借记卡|储蓄卡|银行卡|卡片|白金卡|联名卡|虚拟卡|办.{0,4}卡|申请.{0,4}卡|新卡.{0,2}(到|到手|收到|到了|怎么用|能|激活)|旧卡|原卡号|补发卡|尾号\s*\d{3,4}|哪些卡|有哪几张卡|哪几张卡|的卡|张卡|那张卡|这张卡|我的卡|我卡|名下.{0,2}卡|名下的信用|挂失|补卡|补办|补一张|换卡|到期换卡|损坏换卡|保留原号|保留原卡号|激活|未激活|额度|授信|提额|降额|限制|冻结|解冻|解除限制|刷卡|取现|被盗刷|卡.{0,3}(丢|不见|被偷|被盗|遗失|没|锁|冻))/.test(
      text,
    ) &&
    // 排除纯理财问法:"理财产品的额度"不是卡片
    !/(理财|基金|产品|净值|申购|赎回|持仓)/.test(text);
  /** 挂失:★ 最高优先级 —— 见下方判定顺序 */
  //
  //  ★ 判据写成「提到卡」+「有丢失/冻结的表述」两部分,而不是一个长正则:
  //    曾经写成 `/(卡|卡号)?.*(丢了|...)/`,那个 `.*` 要求中间至少隔一个字,
  //    于是最短也最常见的那句「卡丢了」反而不匹配 —— 而它恰恰是最紧急的一句。
  //    短句里的紧急诉求最容易被判据的细节漏掉,这里刻意把两个条件拆开写。
  const reportsLoss =
    (/(卡|信用卡|借记卡|储蓄卡|银行卡)/.test(text) &&
      /(丢了|找不到了?|不见了|被偷|被盗|遗失|落在|掉在|没了)/.test(text)) ||
    /(挂失|冻结.{0,4}卡|把卡冻|锁卡|先冻|停卡)/.test(text);
  /**
   * 问的是**补办事宜**(多久能好、要不要换号),而不是"卡丢了"这件事。
   *
   * ★ 这个区分是本场景最容易做错的一处顺序问题。实测原话:
   *   「挂失后补办要多久能不能保留原卡号」
   *   这句话里同时有"挂失"和"补办",而早期判据把"挂失"排在前面,
   *   于是系统**又冻结了一遍**,却完全没有回答"要多久"。
   *   用户的诉求是了解流程,系统给的却是重复执行一个已经做过的动作。
   *   因此:提到补办/补卡/保留原号/换号,或者问"要多久",就按补办处理。
   */
  const asksReplacement =
    /(补办|补卡|补一张|补发|换卡|换号|保留原号|保留原卡号|卡号不变|多久|多长时间|几个工作日|什么时候能到|什么时候到手)/.test(
      text,
    ) && /(卡|原号|卡号|丢|挂失)/.test(text);
  const isCardLoss = reportsLoss && !asksReplacement;
  const isCardReplace =
    /(补卡|补办|补一张|补发|换一张卡|换卡|重新办一张卡|重办|新卡什么时候|保留原号|保留原卡号|换号)/.test(text);
  const isCardActivate = /(激活|未激活|怎么用.{0,4}新卡|新卡.{0,4}(到手|收到|到了|怎么用|能用))/.test(text);
  const isCardLimit =
    /(额度|授信|提额|涨额|调额|额度太低|额度不够|能不能提)/.test(text) &&
    !/(限额|限额设置|转账限额)/.test(text);
  const isCardRestriction =
    /(被限制|限制了|怎么刷不|刷不了|刷不了卡|被锁|锁了|用不了|不能刷|交易受限|支付失败|被冻|冻结了|解冻|解除限制|解开|为什么被限制|解除冻结)/.test(
      text,
    );
  const isCardNewApplication =
    /(办一张|办张|申请一张|申请张|想办.{0,4}卡|新办卡|开卡|新开户|加办|再申请一张|办个卡|申请.{0,4}信用卡|办.{0,3}信用卡)/.test(
      text,
    ) && !isCardReplace;
  const isCardList = /(有哪些卡|哪些卡|我的卡|名下.{0,4}卡|几张卡|卡都|所有卡|看看卡|有哪几张卡)/.test(text);
  const isCardDetail =
    /(额度多少|额度是多少|这张卡|那张卡|卡片详情|卡的详情|到期|有效期|还款日|账单日|尾号\s*\d{4}\s*(那张|的卡)?)/.test(
      text,
    );

  // 卡片动作判定顺序(更具体的优先):
  //   ★ ① 挂失 —— **永远排第一**。它同时含"卡"与"丢",而"卡丢了要补办"
  //          这类句子里还有"补办"字样;若把补卡排在前面,系统会在
  //          客户最需要止损的那一刻先问"换号还是保留原号"。
  //     ② 激活 / 补卡 / 解除限制 / 新办卡 / 提额
  //     ③ 只读查询(卡列表 / 详情 / 提额资格)
  const isCardIntent =
    cardCue &&
    (isCardLoss ||
      isCardActivate ||
      isCardReplace ||
      isCardRestriction ||
      isCardLimit ||
      isCardNewApplication ||
      isCardList ||
      isCardDetail ||
      /(卡)/.test(text));

  // ==========================================================================
  // 订阅代扣场景(新场景)的意图识别
  //
  // ★ 判据的设计难点只有一个:**与 `account.recurring` 抢句子**。
  //   「我有哪些订阅」这句话在账单分析里已经有归属(定期支出与订阅),
  //   而且那是**正确的**归属 —— 客户问的确实是"我有哪些",不是"帮我关掉"。
  //   所以本场景的识别必须遵守两条:
  //
  //     ① 查询类只在出现**代扣专属词**时接管:「代扣 / 自动扣费 / 自动扣款 /
  //        自动续费 / 签约」—— 这些词在账单分析的语境里根本不出现;
  //     ② 办理类由**取消动词 + 订阅对象**触发,且优先级高于 isRecurring,
  //        否则「把爱奇艺会员关了」会落进"定期支出分析"——
  //        系统会给出一份分析报告,而客户要的是把那笔钱停掉。
  //        **听上去像回答了,实际上什么都没办** —— 本场景最严重的一类故障。
  //
  // ★ 为什么取消动词单独写一个正则,而不是复用上面的 cancelVerb:
  //   cancelVerb 里没有"关了"。而「把爱奇艺会员关了」恰恰是需求原文里
  //   客户的说法 —— 最真实的那一句不能漏。
  //   同时"关了"这个词**不能**加进通用 cancelVerb:那会让
  //   「把卡关了」「把理财关了」之类的句子改变原有归属,动到已有逻辑。
  //   新增场景新增判据,不修改既有判据 —— 这是本项目的改造纪律。
  // ==========================================================================
  /** 订阅/代扣的专属名词(账单分析语境里不出现的那些) */
  const subCue =
    /(代扣|自动扣费|自动扣款|自动扣钱|自动续费|自动订阅|签约代扣|免密支付|连续包月|包月服务|订阅服务|续费提醒|订阅管理|代扣协议)/.test(
      text,
    );
  /**
   * ★ 取消订阅的动词。
   *
   * 「关了」必须包含(需求原话「把爱奇艺会员关了」);
   * 「退订」「解约」「别再扣」「不想续了」是真实对话里的高频同义说法。
   */
  const subCancelVerb =
    /(取消|关掉|关了|关闭|停掉|停了|终止|解除|解约|退订|不再续费|不想续|别再扣|不要再扣|别扣了|不续了|不要了|帮我关)/.test(
      text,
    );
  /** 用户提到了某个"订阅对象"(会员/订阅/代扣/续费/云盘/保险 这类字眼) */
  const subObjectCue = /(会员|订阅|代扣|续费|包月|自动扣|VIP|vip|云空间|云盘|网盘|课程|网课|健身|月卡|保险|保障)/.test(text);
  /**
   * ★ 单靠取消动词就能确定是订阅代扣的说法 —— 这些说法里**自带**"扣款/合约"的意思:
   *   「别再扣了」「不续了」「退订」「解约」。
   *   少这一条会漏掉最口语、也最常见的那几句(实测「别再扣了」会因为
   *   句子里既没有"会员"也没有"代扣"而掉进转账分支,被回一句"要转给谁")。
   */
  const subSpecificCancelVerb = /(退订|解约|别再扣|不要再扣|别扣了|不再续费|不想续|不续了|取消自动续费|关掉自动续费|取消自动扣费|关掉自动扣费)/;
  /** 取消订阅的完整判据:取消动词 + (订阅对象 或 代扣专属词) */
  const isSubCancel = (subCancelVerb && (subObjectCue || subCue)) || subSpecificCancelVerb.test(text);
  /**
   * 续费提醒:问的是"什么时候扣、扣多少"。
   *
   * ★ 与 isRecurring 的分工:账单分析的「每月固定支出」问的是**过去**的规律;
   *   续费提醒问的是**接下来**还会被扣什么。判据落在"往后"的词上:
   *   「快到期」「什么时候扣」「还要扣多少」「续费提醒」。
   */
  const isSubRenewal =
    /(续费提醒|要到期|快到期|即将到期|什么时候扣|何时扣|哪天扣|还要扣多少|这个月还要扣|接下来.*(扣|续费)|下个月.*(扣|续费)|提醒我.*(扣|续费)|到期提醒)/.test(
      text,
    ) ||
    (/到期/.test(text) && subObjectCue);
  /**
   * 自动识别 / 清单:要求"代扣/自动扣/签约"这类专属词,
   * 从而把「我有哪些订阅」原样留给账单分析(account.recurring)。
   */
  const isSubScan =
    subCue ||
    /(哪些.*(自动扣|代扣)|有没有.*(自动扣|代扣|乱扣)|查.*(代扣|自动续费)|识别.*订阅|订阅.*(扫描|梳理|体检))/.test(text);
  /** 单笔详情:问某笔订阅"多少钱 / 什么时候扣" */
  const isSubDetail = subObjectCue && /(多少钱|多少|什么时候|哪天|详情|明细|怎么样|查一下|看看)/.test(text) && !isSubScan;

  const isSubIntent = isSubCancel || isSubScan || isSubRenewal || isSubDetail;

  // ==========================================================================
  // 跨场景事件联动(新场景)的意图识别
  //
  // ★ 这里最容易犯的错是"抢词":本场景的触发词里天然带着别的场景的词 ——
  //   「大额支出」属于账单分析、「发工资」属于收支查询、「旅游」属于消费。
  //   判据必须落在**"要规划"这个动作**上,而不是落在事件名词上:
  //     「最近有什么大额支出」        → 账单分析(只是问过去)
  //     「最近有什么大额支出需要提前准备」→ 事件联动(问的是往后怎么办)
  //   差的就是"要准备"三个字。所以本场景统一要求:**事件名词 + 规划动作**。
  // ==========================================================================

  /** 事件名词:客户生活里的关键事件 */
  const eventNoun =
    /(纪念日|周年|结婚纪念|领证|生日|寿辰|过生|发薪日|发薪|发工资|开工资|工资到账|月薪到账|薪水到账|大额支出|大额开销|大笔支出|固定扣款|集中扣款|旅游|旅行|出游|出去玩|度假|出行|自驾)/.test(
      text,
    );
  /** 规划动作:出现它才说明客户要的是"方案",不是"一份查询结果" */
  const eventPlanVerb =
    /(规划|计划|安排|帮我准备|提前准备|提前安排|准备一下|要准备|怎么安排|提前多久|提醒我|有什么.*需要|需要.*(准备|留意|提前)|帮我筹划|筹划|日程)/.test(
      text,
    );
  /**
   * ★ 登记事件(auto 级写操作):"记一下 + 事件名词"。
   *   与规划分开的理由:登记只写客户自己的日程,不需要方案,也不需要确认;
   *   而规划要读一堆银行数据、生成待确认步骤。两件事的量级完全不同。
   */
  const isEventRegister =
    /(记一下|帮我记|记录一下|登记|记下来|备注一下|存一下)/.test(text) && eventNoun && !/方案|规划/.test(text);
  /** 触发器/事件清单:问"你能帮我规划什么""我有哪些重要日子" */
  const isEventList =
    /(有哪些|有什么|都有哪些|列一下|看看).{0,8}(触发器|关键事件|重要日子|重要事件|纪念日|生日|日程)/.test(text) ||
    /(能规划什么|能帮我规划什么|可以规划什么|支持哪些事件|有哪些触发器)/.test(text);
  /**
   * 执行方案里的步骤。
   *
   * ★ 判据必须包含"执行"意图,否则「先锁定资金」这种泛指会被当成对方案的执行。
   *   三类说法都要接住:① 按类别说(执行资金操作/外部那步);
   *   ② 按序号说(执行第2步);③ 按动作说(帮我订花/把礼物预算留出来)。
   */
  const isEventFundStep =
    /**
     * ★ 按类别说(「执行资金操作」「资金那一步」)或**按序号说**
     *   (「执行第2步」「办第二步」「落实第 3 步」)。
     *   序号判据收在 `intent/eventWording.ts`:它与编排器里"方向判据"必须完全一致,
     *   而原来这里只认「第一步/第1步」—— 于是「执行第2步」掉进了转账意图,
     *   被解析成"转给「执行第」2 元",系统当场开始问金额(实测复现)。
     */
    /(执行|办|走|按|开始|落实).{0,6}(资金操作|资金那步|资金那一步)/.test(text) ||
    isOrderedStepExecutionSpoken(text) ||
    /(锁定|预留|冻结|留出|划出|扣住).{0,10}(资金|预算|钱|这笔)/.test(text) ||
    /**
     * ★ 语序反过来同样常见:「先把礼物预算留出来」—— 用途在前、动作在后。
     *   少了这一条,这句话会掉进账户侧的**预算规划**(句子里有"预算"),
     *   于是客户要办的事被换成了"帮你规划一下这个月预算"。
     *   判据要求动作是"留出来/留一笔"这种**留下钱**的说法,而不是"预算多少"。
     */
    /(资金|预算|钱|这笔).{0,8}(留出来|留出一笔|留一笔|预留出来|锁起来|锁上|先留着)/.test(text) ||
    /** ★ 解开预留:两种语序都收(「取消刚才那个预留」「把预留解开」) */
    isEventReleaseSpoken(text);
  const isEventExternalStep =
    /(执行|办|走|提交|确认|下单|订购).{0,8}(外部|外部服务|外部订单|商户|订购|下单)/.test(text) ||
    /(帮我|替我|直接)?(订|订一束|订个|预订|预定|下单|买一束|叫个|叫一份)/.test(text) &&
      /(花|蛋糕|餐厅|酒店|房|套餐|机票|门票|礼物)/.test(text);
  /** 规划:事件名词 + 规划动作,且不是在问"有哪些" */
  const isEventPlan =
    (eventNoun && eventPlanVerb && !isEventList) ||
    (/(帮我规划|规划一下|安排一下|帮我安排)/.test(text) && !/(预算|理财|基金|产品|花多少|省钱|省点)/.test(text));
  const isEventIntent =
    isEventPlan || isEventList || isEventRegister || isEventFundStep || isEventExternalStep;

  // 理财动作判定顺序(更具体的优先):
  //   ① 签确认书 —— 法律上的独立意思表示,必须单独接住
  //   ② 赎回     —— 与申购互斥,说了赎回就不该被理解成买
  //   ③ 持仓查询 —— "我买的理财赚了多少"里含"买"字,必须先于申购判断
  //   ④ 测评
  //   ⑤ 对比     —— "这个和那个比哪个收益高"
  //   ⑥ 详情     —— "这个产品起购多少""多久能到账"
  //   ⑦ 申购
  //   ⑧ 列表/推荐
  //   ⑨ 兜底:说了金额 + 理财语义词但没给动作词("我有5万块买理财")
  const isWealthIntent =
    isSignConsent ||
    isRedeem ||
    isRedeemOrdinal ||
    isHolding ||
    isAssessment ||
    isCompare ||
    isDetail ||
    isBuyOrdinal ||
    isPurchase ||
    isVagueWealth ||
    isOrdinalWealth ||
    isProductList ||
    (wealthCue && Boolean(amount));

  // ---- 账单分析场景(场景二)的意图识别 ----
  // ★ 顺序很重要:更具体的意图优先于泛化的"分析/查询"。
  //   例如"这个月账单有没有异常"必须先命中"异常",而不是被"账单"拉去查流水。
  const isReport =
    /(账单报告|账单总结|月报|年报|月度账单|年度账单|本月账单|上月账单|这个月.*(总结|汇总)|今年.*(总结|汇总))/i.test(
      text,
    );
  const isAnomaly =
    /(异常|可疑|不对劲|盗刷|不认识|没印象|奇怪|莫名其妙)/.test(text) ||
    (/大额/.test(text) && /(支出|消费|交易|扣|账单)/.test(text));
  const isRecurring =
    /(订阅|会员|自动扣|自动续费|定期扣|固定支出|每月.*扣|月供|续费|定期支出|固定扣款)/.test(text);
  const isCashflow =
    /(收支|现金流|入账|赚了多少|存下|储蓄|结余|存了多少|每个月.*(存|剩))/i.test(text);
  const isInsight =
    /(省钱|省点|建议|消费习惯|帮我看.*(花钱|账单|支出)|怎么优化|哪里可以省)/.test(text);
  /**
   * ★ 预算规划意图。
   *
   * 必须**先于** isAnalysis / isInsight 判断:
   *   「这个月预算还剩多少」里的"还剩"与"多少"很容易被拉去"分析花了多少",
   *   而用户问的是**事前约束**(还能花多少),不是事后归因(已经花了多少)。
   *   两者答错一个,数字都是对的,但回答的是另一个问题 —— 这类静默错误最难被发现。
   */
  const isBudget =
    /(预算|计划花|打算花|花多少合适|能花多少|每天能花|每天可以花|剩余.{0,4}(额度|预算|钱)|还剩多少能花|还能花多少|控.{0,2}预算|超支|够不够花)/.test(
      text,
    ) && !/(理财|基金|申购|赎回|产品)/.test(text);
  const isQuery = /(余额|多少钱|流水|账单|消费|花了|明细|查询)/.test(text) && !/转(账|给)/.test(text);
  // 催收:在状态查询基础上再区分"催他们一下"
  const isCollectionRemind = isCollectionStatus && /(催|提醒|催一下|催收|问他们要)/.test(text);

  /**
   * ★ 材料比对(账单分析之上的扩展能力,不占场景编号)。
   *
   * 判据必须同时有"比对动作词"和"材料名词":只说"对比"可能是比理财产品,
   * 只说"合同"可能是在问合同能不能转账。两者同时出现才是在看材料。
   * 另加一条"差异描述"入口:「合同和发票金额对不上」这种话里没有"比对"两个字,
   * 但意思比任何问法都明确。
   */
  const isDocCompare =
    (/(比对|对比|核对|对照|检查|看看|看一下|看下|查一下|审一下)/.test(text) &&
      /(材料|合同|发票|报价|单据|凭证|回单)/.test(text)) ||
    /(合同|发票|报价单|材料|单据).{0,12}(对不上|不一致|矛盾|不一样|有出入|差(了|多少)|有没有问题)/i.test(text) ||
    /(几份|两份|三份).{0,6}材料/.test(text);

  /**
   * ★ 异常复核(账单分析之上的扩展能力,不占场景编号)的两类话:决定"要不要再扫"、以及"这条是误报,撤掉"。
   *
   * 顺序必须早于 isAnomaly:否则「再扫一遍异常」会被当成一次普通的异常识别,
   * 系统就变成了客户说一句、它就无脑重扫一遍 —— 正是需求点名不要的行为。
   */
  const isAnomalyWithdraw =
    /(误报|撤回|撤掉|撤销|不是异常|不算异常|我自己的|我本人|正常的|删掉这条)/.test(text) &&
    /(异常|可疑|这条|这笔|那笔|记录)/.test(text);
  const isAnomalyReview =
    /(再扫|重扫|重新扫|再查|再检查|再跑|复核|复查|还有(没有|哪些|多少)|漏(了|掉)?|覆盖)/.test(text) &&
    /(异常|可疑|交易|账单|记录)/.test(text);

  /**
   * ★ 制度问答(阶段 1)。
   *
   * 判据 = 「制度话题」+「问句形状」,并排除两类:
   *   ① 问的是**我自己的数据**(我的额度/我的余额/上个月那笔)→ 交给结构化能力或记忆检索;
   *   ② 明确在**办一件事**(帮我转/补办/激活/提到 X 万)→ 交给对应业务动作。
   *   唯一例外:问的是"费用"时,「补卡多少钱」这种既是动作词又是费用问句的,
   *   归制度问答 —— 客户问的是价目表,不是要现在补卡。
   *
   * ★ 为什么这条必须排在卡片/理财判断之前:
   *   「赎回多久到账」里有"赎回",不先判制度就会被拉去做赎回流程;
   *   「补卡多少钱」里有"补卡",不先判就会被当成要补办一张卡。
   *   而「挂失后补办要多久能不能保留原卡号」是**真的**在办补卡 ——
   *   所以"动作词 + 非费用问句"必须排除掉它。
   */
  const policyTopic =
    /(年费|免年费|工本费|补卡费|手续费|管理费|服务费|账户管理费|收费标准|收费|收钱|要钱)/.test(text) ||
    /(挂失|补卡|补办)/.test(text) ||
    /(测评|评估).{0,6}(有效期|多久|有效)|先做.{0,6}测评|需要.{0,6}测评|要.{0,6}测评/.test(text) ||
    /(多久到账|几天到账|到账时间|到账时效)/.test(text) ||
    /(份额.{0,4}确认|确认份额)/.test(text) ||
    /(大额赎回|提前.{0,4}预约|预约赎回)/.test(text) ||
    /(新收款人|首次.{0,4}(转账|汇款)|人脸识别|刷脸|要人脸)/.test(text) ||
    /(拆分交易|拆分|可撤销|撤销窗口|转错.{0,4}(撤销|退))/.test(text) ||
    /(争议|有疑问|疑问|盗刷|交易纠纷)/.test(text) ||
    /汇率/.test(text);
  const policyAsk =
    /(吗|多少|多久|多长时间|几天|几个工作日|怎么|如何|能不能|可以吗|要不要|是否|规则|规定|标准|时限|什么时候|哪里|窗口|期限|上限|门槛)/.test(
      text,
    );
  /** 问的是"价目/费率":这类问题即使带着动作词,也是在问制度 */
  const policyFeeQuestion = /(多少钱|贵多少|收钱|收费|费用|费吗|手续费|年费|工本费|管理费|要钱)/.test(text);
  /** 明确在办一件事(排除) */
  const policyDoing =
    /(帮我|给我|我想办|麻烦你|转给|再转|买[0-9零一二三四五六七八九十百千万]|申购[0-9]|全部赎回|赎回过?半|补办|补卡|挂失先|先挂失|激活|办一张|办张|提到\s*[0-9]|提额到)/.test(
      text,
    );
  /** 问的是客户自己的数据(排除) */
  const policyMyData = /(我的额度|我的余额|我的持仓|我上个月|我这笔|那笔转账|我那张卡|我还有多少)/.test(text);
  const isPolicyQuestion =
    policyTopic && policyAsk && !policyMyData && (!policyDoing || policyFeeQuestion);

  /**
   * ★ 客户记忆检索(阶段 2)。
   *
   * 判据 = 「过去时间/指代」+「一件办过的事」。
   * 这类问句的危险在于:它含业务动词(转账/理财),但时态是**过去**——
   * 如果不先接住,系统会把它当成一笔新业务去追问"转给谁、转多少"。
   * 客户在问过去,系统却在催他再转一笔,这是最典型的答非所问。
   */
  const isMemoryQuestion =
    !/(撤销|撤回|退回|取消|退了|误报|不是异常|不算异常|我自己的|正常的|不要这?笔)/.test(text) &&
    (/(刚才|刚刚|上次|上个月|昨天|前天|之前|那笔|这笔|那次|最近.{0,4}(那|这)?笔?).{0,10}(转账|汇款|操作|办的|办成|办完|成功|失败|到账|结果|进度|处理|批了|成了|好了)/.test(
      text,
    ) ||
      /(那笔|这笔|刚才那笔|上次那笔).{0,6}(怎么样了|怎么样|成了吗|成功了吗|到账了吗|有没有成功)/.test(text));

  let action: Intent["action"] = "transfer.send";  // ★ 顺序即优先级。几条容易互相误伤的规则按"更具体优先"排列:
  //   ⓪ 卡片场景  必须早于理财与转账 —— 「信用卡额度太低能不能提额」里
  //                "额度"与理财无关,若不先判,它会去找理财产品;
  //   ① 理财场景  必须早于转账兜底 —— "我有5万块,推荐几个理财产品"里有金额,
  //                若排在后面前面,会被当成一笔 5 万元的转账去追问收款人;
  //   ② 取消定时任务 必须早于 isSchedule(否则"取消定时转账"被当成创建);
  //   ③ AA 状态/催收  必须早于 isCollection(否则"AA 进度怎么样"被当成发起收款);
  //   ④ 撤销已转出的钱 早于普通转账。
  if (isPolicyQuestion) action = "policy.search";
  else if (isMemoryQuestion) action = "memory.search";
  else if (isCardIntent) {
    // ★ 「为什么被限制」与「帮我解开」必须分开:
    //   前者只读(查原因),后者是"放宽敞口"方向(提交解除申请)。
    //   把它们混成一个动作,系统就会在客户只是想知道原因时,
    //   直接替他提交一份解除申请 —— 而需求里点名禁止的正是这件事。
    const asksWhy =
      /(为什么|为啥|什么原因|原因|怎么回事|查一下|看看|怎么回|为什么被)/.test(text) &&
      !/(帮我解|帮我解除|提交|申请解除|解一下|解开|解冻|解除限制)/.test(text);
    const asksUnblock = /(帮我解|帮我解除|提交|申请解除|解一下|解开|解冻|解除限制|给我解)/.test(text);

    if (isCardLoss) action = "card.report_loss";
    else if (isCardActivate) action = "card.activate";
    else if (isCardReplace) action = "card.replace";
    else if (isCardRestriction) action = asksUnblock && !asksWhy ? "card.unblock" : "card.restrictions";
    else if (isCardNewApplication) action = "card.new_application";
    else if (isCardLimit) {
      if (/(进度|到哪|批了|结果|审核多久|下来了吗)/.test(text)) action = "card.limit_status";
      else if (asksLimitAmount(text)) action = "card.limit_adjust";
      else action = "card.limit_eligibility";
    } else if (isCardList) action = "card.list";
    else if (isCardDetail) action = "card.detail";
    else action = "card.list";
  } else if (isSubIntent) {
    // ★ 顺序说明(为什么排在卡片之后、理财之前):
    //   ① 卡片在前 —— 「把那张卡的自动续费关了」里的"卡"必须先被卡片场景接住;
    //   ② 理财与转账在后 —— 订阅场景里没有"收款人"也没有"申购金额",
    //      排在这里才不会掉进转账兜底被追问"转给谁"。
    //
    // ★ 四个子动作的判定顺序:**办理 > 提醒 > 识别 > 详情**。
    //   客户说「把爱奇艺会员关了」时句子里也可能有"多少钱"(「关了那个19块的会员」),
    //   若详情判据排在前面,它会被当成一次查询 —— 客户要办的事被降级成一次回答。
    if (isSubCancel) action = "subscription.cancel";
    else if (isSubRenewal) action = "subscription.list";
    else if (isSubScan) action = "subscription.scan";
    else action = "subscription.detail";
  } else if (isEventIntent) {
    /**
     * ★ 顺序说明(为什么排在订阅之后、理财之前):
     *   ① 订阅在前 —— 「取消自动续费」这类话必须留在订阅场景里,
     *      本场景的"取消预留"只在明确提到**预留/锁定/定时任务**时才成立;
     *   ② 理财/转账在后 —— 本场景的句子里没有收款人也没有申购金额,
     *      排在前面才不会被转账兜底追问"转给谁"。
     *
     * ★ 子动作顺序:**办理 > 登记 > 清单 > 规划**。
     *   与订阅场景同一条教训:客户说「帮我订花」时句子里可能也提到"纪念日",
     *   若规划判据排在前面,一次**办理**就被降级成"我再给你出一份方案"。
     */
    if (isEventExternalStep) action = "event.external_step";
    else if (isEventFundStep) action = "event.fund_step";
    else if (isEventRegister) action = "event.register";
    else if (isEventList) action = "event.list";
    else action = "cross_scene_event_planning";
  } else if (isWealthIntent) {
    action = isSignConsent
      ? "wealth.sign_consent"
      : isRedeem || isRedeemOrdinal
        ? "wealth.redeem"
        : isHolding
          ? "wealth.holdings"
          : isAssessment
            ? "wealth.risk_assess"
            : isCompare
              ? "wealth.compare"
              : isDetail
                ? "wealth.product_detail"
                : isBuyOrdinal
                  ? "wealth.purchase"
                  : isOrdinalWealth
                    ? // 位置指代但没命中上面的具体分支:交给路由层按序号决定详情还是对比
                      /(对比|比较|比一下|比一比|哪个|区别)/.test(text)
                      ? "wealth.compare"
                      : "wealth.product_detail"
                    : isPurchase
                      ? "wealth.purchase"
                      : "wealth.list_products";
  } else if (isSecurity) action = /密码/.test(text) ? "security.change_password" : "security.change_phone";
  else if (isCancelSchedule) action = "transfer.cancel_schedule";
  else if (isCollectionStatus) action = isCollectionRemind ? "collection.remind" : "collection.query";
  else if (isCancel) action = "transfer.cancel";
  else if (isNote) action = "note.create";
  else if (isCollection) action = "collection.create";
  // ★ 材料比对与异常复核必须早于 isReport / isAnomaly:
  //   「比对合同和发票」里没有"报告"字样但含"账单"类词时会被误判;
  //   「再扫一遍异常」若落到 isAnomaly,系统就会无脑重扫 —— 正是要避免的行为。
  else if (isDocCompare) action = "document.compare";
  else if (isAnomalyWithdraw) action = "account.anomaly_withdraw";
  else if (isAnomalyReview) action = "account.review_anomalies";
  else if (isReport) action = "account.report";
  else if (isAnomaly) action = "account.anomalies";
  else if (isRecurring) action = "account.recurring";
  else if (isCashflow) action = "account.cashflow";
  else if (isInsight) action = "account.insights";
  else if (isBudget) action = "account.budget_plan";
  else if (isAnalysis) action = "account.analysis";
  else if (isList) action = "account.transactions";
  else if (isQuery) action = /流水|明细|账单|消费|花了/.test(text) ? "account.transactions" : "account.balance";
  else if (isSchedule) action = "transfer.schedule";

  // 查询参数:分析/报告/异常/定期/收支类都需要从原文推断时间范围
  const query =
    isAnalysis || isList || isReport || isAnomaly || isRecurring || isCashflow || isInsight
      ? extractQueryParams(text, now)
      : undefined;

  // AA 收款解析
  let collection: Intent["collection"];
  if (action === "collection.create") {
    const participants = extractParticipants(text);
    collection = {
      title: extractCollectionTitle(text),
      totalAmount: amount ?? { value: 0, currency: "CNY", raw: text, derived: false },
      splitMode: "equal",
      participants: participants.length >= 2 ? participants : [],
      feeBearer: "each",
      allowPartial: false,
      shareLink: true,
    };
    if (participants.length < 2) missing.push("participants");
  }

  // 理财参数(场景三)
  const wealth = isWealthIntent ? extractWealthRef(text) : undefined;
  // 卡片参数(场景四)
  const card = isCardIntent ? extractCardRef(text) : undefined;
  // 订阅代扣参数(新场景)
  const subscription = isSubIntent ? extractSubscriptionRef(text) : undefined;
  // 跨场景事件联动参数(新场景)
  const event = isEventIntent ? extractEventRef(text) : undefined;

  // ★ 理财意图下不要把"金额"塞进 missingSlots。
  //   因为"我有5万块,推荐几个理财产品"里的 5 万是**预算**,不是必须补的槽位 ——
  //   如果把它标成缺失,系统会先追问"要转多少钱",用户当场就懵了。
  //   同理"payee"对理财毫无意义,必须剔除。
  if (isWealthIntent) {
    const filtered = missing.filter((m) => m !== "payee" && m !== "amount");
    missing.length = 0;
    missing.push(...filtered);
  }

  // ★ 卡片意图同理:卡场景里没有"收款人",也没有必须补的"金额"。
  //   不提额的时候金额毫无意义;提额时目标额度由 requestedLimit 表达,
  //   而不是靠通用的 amount 槽位 —— 否则系统会问"要转多少钱"。
  if (isCardIntent) {
    const filtered = missing.filter((m) => m !== "payee" && m !== "amount");
    missing.length = 0;
    missing.push(...filtered);
  }

  // ★ 订阅代扣意图同理:句子里没有"收款人",金额(如果有)是**每期扣费金额**,
  //   由引擎从代扣协议里取,而不是用户要转出去的钱。
  //   留着 amount 槽位会让系统追问"要转多少钱" —— 又一次答非所问。
  if (isSubIntent) {
    const filtered = missing.filter((m) => m !== "payee" && m !== "amount");
    missing.length = 0;
    missing.push(...filtered);
  }

  /**
   * ★ 事件联动意图同理:句子里没有"收款人";金额(如果有)是**预算**,
   *   不是"要转出去多少钱"。留着这两个槽位会让系统追问"转给谁""转多少" ——
   *   而客户说的是"帮我规划",他等的是方案,不是一句追问。
   *
   * ★ 例外:执行方案里的**资金步骤**时,金额与去向**必须**来自方案步骤,
   *   此时也不该由通用槽位来问 —— 缺了就直接回"这一步没说清"(策略引擎的硬规则)。
   */
  if (isEventIntent) {
    const filtered = missing.filter((m) => m !== "payee" && m !== "amount");
    missing.length = 0;
    missing.push(...filtered);
  }

  // 预算规划参数(场景二延伸):与 collection/wealth/card 同样的可选块
  let budget: Intent["budget"];

  // ★ 预算意图:没有"收款人",金额是**预算额**而不是"要转多少钱"。
  //   与理财/卡片同一处理:把它塞进 amount 槽位会让系统追问"要转多少钱"。
  //   同时把预算额填进语义明确的 `budget` 字段(而不是通用的 amount)——
  //   预算与"转出去多少钱"是两件相反的事,共用一个字段迟早会被混用。
  if (action === "account.budget_plan") {
    const filtered = missing.filter((m) => m !== "payee");
    missing.length = 0;
    missing.push(...filtered);
    if (amount?.value) {
      budget = { total: amount.value };
    }
  }

  const confidence = computeConfidence({ payee, amount, action, text });

  return {
    action,
    restatedIntent: buildRestatement({
      action,
      payee: isWealthIntent || isCardIntent || isSubIntent || isEventIntent ? undefined : payee,
      amount,
      text,
    }),
    // ★ 理财与卡片意图下**绝不**带 payee。
    //   实测踩到:「买第4个5万」被抽出一个收款人「买第」(by=alias),
    //   于是赎回追问里冒出一句「转给「卖第」」—— 理财根本没有收款人这个概念。
    //   这个字段一旦被带进理财意图,就会污染确认卡与追问文案。
    //   卡片场景同理:句子里出现的人名(如"我妈的卡")不是收款人。
    ...(payee && !isWealthIntent && !isCardIntent && !isSubIntent && !isEventIntent ? { payee } : {}),
    ...(amount ? { amount } : {}),
    ...(memo ? { memo } : {}),
    ...(schedule ? { schedule } : {}),
    ...(fromAccount ? { fromAccount } : {}),
    ...(collection ? { collection } : {}),
    ...(wealth ? { wealth } : {}),
    ...(card ? { card } : {}),
    ...(subscription ? { subscription } : {}),
    ...(event ? { event } : {}),
    ...(budget ? { budget } : {}),
    missingSlots: [...new Set(missing)],
    confidence,
    ambiguities: [],
    ...(query ? { query } : {}),
  };
}

/**
 * 抽取理财指代(产品 / 风险偏好 / 对比对象 / 份额 / 作答)。
 *
 * ★ 这里只做**指代抽取**,不做产品认定:
 *   "那个稳健型的" → productName="那个稳健型的" + riskPreference="R2",
 *   到底是哪只产品由银行目录的产品定位器决定。
 *   解析器如果自己去猜产品代码,就等于绕过了"产品必须来自银行侧"这条约束。
 */
function extractWealthRef(text: string): Intent["wealth"] {
  const w: NonNullable<Intent["wealth"]> = {};

  // 1) 明确写出的产品代码
  const code = text.match(/LC\d{4}/i);
  if (code) w.productCode = code[0].toUpperCase();

  // 2) 风险偏好词 → R 等级
  //
  //    ★ 只有在**没有说出具体产品名**时才推档位。
  //    实测踩到的坑:用户说「帮我买1万块固收+双利180天」——
  //    里面有个"固收",档位判据就给出了 R2 + fixed_income,
  //    而这只产品其实是 R3 的混合类。于是系统按 R2 去筛,
  //    把用户点名的产品排到了后面,最后定型成了**另一只产品**。
  //    "用户已经说了买哪只"的时候,任何从词面推出来的档位都是多余的,
  //    而且是有害的 —— 它会跟用户的原话打架。
  const hasNamedProduct =
    /LC\s*\d{4}/i.test(text) ||
    /[\u4e00-\u9fa5]{2,10}(?:增利|添利|货币|纯债|双利|配置|指数增强|精选|存单)/.test(text);
  if (!hasNamedProduct) {
    if (/(激进|进取|高风险|股票型|权益)/.test(text)) w.riskPreference = "R5";
    else if (/(成长)/.test(text)) w.riskPreference = "R4";
    else if (/(平衡|混合|中风险)/.test(text)) w.riskPreference = "R3";
    else if (/(稳健|中低|债券|债基|纯债|固收)/.test(text)) w.riskPreference = "R2";
    else if (/(保守|低风险|货币|活期|现金管理)/.test(text)) w.riskPreference = "R1";
  }

  // 2b) 产品类型倾向(与档位偏好互补:用户可能只说类型不说档位)
  if (!hasNamedProduct) {
    if (/(货币|活期|现金管理)/.test(text)) w.typePreference = "cash";
    else if (/(债券|债基|纯债|固收)/.test(text)) w.typePreference = "fixed_income";
    else if (/(混合|平衡)/.test(text)) w.typePreference = "mixed";
    else if (/(股票型|权益|指数)/.test(text)) w.typePreference = "equity";
    else if (/(存单|定期存款)/.test(text)) w.typePreference = "deposit";
  }

  // 3) 产品名称/口语指代
  //    ★ 顺序很重要:先试"叫得出名字的",再退化到"那个稳健型的"。
  //      直接对全句做名称捕获会把"帮我买1万块那个稳健型的"里的
  //      "那个稳健型的"整段当成产品名,定位器匹配不上任何产品。
  const quoted = text.match(/[「"']([^」"']{2,20})[」"']/);
  if (quoted?.[1]) w.productName = quoted[1];

  if (!w.productName) {
    // 已知产品名后缀(`X增利`/`X添利`/`X货币`/`X存单` 这类命名习惯)。
    //
    // ★ 踩过的坑(实测复现过两次,都属于"能买错东西"的级别):
    //   前缀 `[\u4e00-\u9fa5]{2,12}` 会把**紧邻的量词/动词一起吃进来** ——
    //     「帮我买1万块科技成长精选」→ 捕获到「块科技成长精选」;
    //     「把科技成长精选赎回一半」  → 捕获到「把科技成长精选」。
    //   这两个名字在目录里都查不到,于是定位器退化成"取关键词检索的第一条",
    //   用户说要买 R5 的高风险产品,系统却给他定位到 R4 的另一只。
    //   这不是"理解得不够好",而是**会办错事**,必须从判据上修掉:
    //   从后缀锚点向前取字符,并在遇到量词/动词/介词时立即停下。
    const tail = text.match(/([\u4e00-\u9fa5A-Za-z0-9]{2,12}(?:增利|添利|货币|纯债|双利|混合|指数增强|精选|存单|理财\d*))/);
    if (tail?.[1]) {
      const cleaned = stripProductNamePrefix(tail[1]);
      if (cleaned.length >= 2) w.productName = cleaned;
    }
  }

  if (!w.productName) {
    // 口语指代:"那个稳健型的""上次买的那个""这个"
    const colloquial = text.match(
      /((?:那个|这个|上次买的那个|上回买的那个|之前买的那个|原来买的那个)[\u4e00-\u9fa5]{0,6}(?:型|的)?)/,
    );
    if (colloquial?.[1] && colloquial[1].length >= 2) w.productName = colloquial[1];
  }

  if (!w.productName && /(基金|理财产品?|理财)/.test(text) && !/(推荐|哪些|有什么|几个)/.test(text)) {
    // 用户只说了"基金/理财"这一类词,不构成具体产品指代 —— 保持 undefined,
    // 让编排器去澄清或列出候选,而不是硬塞一个产品名。
  }

  // 4) 对比对象:"这个和那个比""A 和 B 哪个收益高"
  if (/(对比|比较|哪个|相比|区别|比一下|比一比)/.test(text)) {
    const pairs = text.match(
      /([\u4e00-\u9fa5A-Za-z0-9]{2,12}(?:增利|添利|货币|纯债|双利|混合|指数增强|精选|存单)?)\s*(?:和|与|跟|、|,|vs|VS)\s*([\u4e00-\u9fa5A-Za-z0-9]{2,12}(?:增利|添利|货币|纯债|双利|混合|指数增强|精选|存单)?)/,
    );
    if (pairs?.[1] && pairs[2]) {
      const targets = [pairs[1], pairs[2]]
        .map((s) => s.replace(/^(这个|那个|帮我|我想|把|和|与)/, "").trim())
        .filter((s) => s.length >= 2 && !/^(哪个|哪个收益|比)/.test(s));
      if (targets.length >= 2) w.compareTargets = targets;
    }
    if (!w.compareTargets) {
      // "这个和那个比" —— 两个指代词,交给编排器按上下文/持仓补全
      if (/(这个|那个|这只|那只)/.test(text)) w.compareTargets = [];
    }
  }

  // 4b) ★ 位置指代:「第1个和第3个」「前两个」「1和3」
  //     ★ 这里只做**序号抽取**,绝不翻译成产品名 ——
  //       序号的含义依赖"刚才展示的那份列表",那只有编排器知道。
  //       解析器如果自己映射成产品,就是在编造一个它无从验证的指代。
  const ordinalRefs = extractOrdinalRefs(text);
  if (ordinalRefs.length > 0) w.ordinalRefs = ordinalRefs;

  // 5) 赎回:份额 / 全额
  if (/(全部|全都|全赎|都赎|一次全|清仓)/.test(text)) w.redeemAll = true;
  const shares = text.match(/(\d[\d,]*(?:\.\d+)?)\s*(?:份|份额)/);
  if (shares?.[1]) w.shares = Number(shares[1].replace(/,/g, ""));

  // 6) 测评作答:"a b c d e c" 这类一次答完
  const letters = text.match(/(?:^|\s)([a-eA-E](?:[\s,、]+[a-eA-E]){5})(?:\s|$)/);
  if (letters?.[1]) {
    const parts = letters[1].split(/[\s,、]+/).filter((s) => s.length === 1);
    if (parts.length === 6) {
      w.assessmentAnswers = parts.map((p, i) => ({ questionId: `q${i + 1}`, optionId: p.toLowerCase() }));
    }
  }

  return Object.keys(w).length > 0 ? w : undefined;
}

/**
 * 卡片引用抽取(场景四)。
 *
 * ★ 与 `extractWealthRef` 同一条纪律:这里只做**指代抽取**,不做卡片认定。
 *   "尾号 1234 那张" → last4="1234";究竟是哪张卡、状态如何,
 *   由银行核心的卡片目录决定。解析器如果自己判断"这张卡是正常状态",
 *   就等于让模型参与了风控判断。
 *
 * ★ 三条克制(每一条都对应一类会造成实际损失的错误):
 *   ① 目标额度只在用户**明确说了数**时才给。
 *      「能不能提额」不带额度 → 系统先答资格,不编一个数字出来;
 *   ② 补卡方式没提就**留空** —— 由系统展示"换号 5 天 / 保号 12 天"的差异让用户选。
 *      替用户默认成"换号"看起来贴心了,实际上剥夺了他在知情后选择的权利;
 *   ③ 序号只抽取、不翻译(与理财场景同一条原则)。
 */
function extractCardRef(text: string): Intent["card"] {
  const c: NonNullable<Intent["card"]> = {};

  // 1) 卡号后四位 —— 用户最常用的指认方式
  const last4 = text.match(/(?:尾号|后四位|末四位|最后四位)\s*(\d{4})/);
  if (last4?.[1]) c.last4 = last4[1];

  // 2) 卡种倾向
  if (/(信用卡|贷记卡)/.test(text)) c.kindPreference = "credit";
  else if (/(借记卡|储蓄卡|工资卡)/.test(text)) c.kindPreference = "debit";
  else if (/虚拟卡/.test(text)) c.kindPreference = "virtual";

  // 3) 产品名/口语称呼:带引号的最可信,其次常见卡名后缀
  const quoted = text.match(/[「"']([^」"']{2,20})[」"']/);
  if (quoted?.[1]) c.productName = quoted[1];
  if (!c.productName) {
    const named = text.match(/([\u4e00-\u9fa5A-Za-z0-9]{2,12}(?:白金卡|金卡|普卡|联名卡|数字信用卡|信用卡|储蓄卡|借记卡))/);
    if (named?.[1]) c.productName = named[1];
  }

  // 4) 目标额度:只在明确给了数字时才有值
  const target = text.match(/(?:提到|提到多少|提到|提额到|申请到|额度提到|涨到|调到|提到)\s*([0-9]+(?:\.[0-9]+)?)\s*(万|千|元|块|w|k)?/i);
  if (target?.[1]) {
    let v = Number(target[1]);
    const unit = target[2];
    if (unit === "万" || unit === "w" || unit === "W") v *= 10_000;
    else if (unit === "千" || unit === "k" || unit === "K") v *= 1_000;
    if (Number.isFinite(v) && v > 0) c.requestedLimit = v;
  } else {
    // 「把额度提到5万」这种把数字放在前面的说法
    const target2 = text.match(/([0-9]+(?:\.[0-9]+)?)\s*(万|千)?\s*(?:元)?\s*(?:的)?\s*(?:额度|授信)/);
    if (target2?.[1] && /(提到|提到|涨|调|申请)/.test(text)) {
      let v = Number(target2[1]);
      if (target2[2] === "万") v *= 10_000;
      else if (target2[2] === "千") v *= 1_000;
      if (Number.isFinite(v) && v > 0) c.requestedLimit = v;
    }
  }

  // 5) 降额:安全方向,与提额不同路
  if (/(降额|降低额度|额度降|把额度调低|调低额度)/.test(text)) c.decrease = true;

  // 6) 补卡方式
  //
  //    ★ 「能不能保留原卡号」是**询问**,不是选择 —— 这时不能填
  //      replacementMode,系统要先展示两种方案的差异(尤其等待时间),
  //      再由用户决定。把询问当成选择,是最典型的"替用户做决定"。
  const asksKeep = /(能不能|可以|能否|是否|可不可以).{0,6}(保留|不换).{0,4}(原卡号|原号|号码)/.test(text);
  if (!asksKeep) {
    if (/(保留原号|保留原卡号|不换号|不换卡号|卡号不变|还用原来那个号)/.test(text)) c.replacementMode = "keep_number";
    else if (/(换号|换个号|新卡号|换个卡号|换一张新卡)/.test(text)) c.replacementMode = "new_number";
  }

  // 7) 申请单号
  const appId = text.match(/(LMT[_A-Za-z0-9]*|申请单\s*号?\s*[:：]?\s*([A-Za-z0-9_-]{6,}))/);
  if (appId) c.applicationId = appId[2] ?? appId[1];

  // 8) 用户自述(挂失情形 / 解除限制的理由)
  const statement = text.match(/(?:因为|由于|是|情况是)\s*([^。;；]{4,80})/);
  if (statement?.[1] && /(丢|偷|盗|不在|异地|陌生|不是本人|怀疑|信息|证件|过期)/.test(statement[1])) {
    c.statement = statement[1].trim();
  }

  // 9) 位置指代(「第2张」)—— 只抽序号,不翻译
  const ordinalRefs = extractOrdinalRefs(text);
  if (ordinalRefs.length > 0) c.ordinalRefs = ordinalRefs;

  return Object.keys(c).length > 0 ? c : undefined;
}

/**
 * 抽取订阅代扣的指代(商户名 / 协议号 / 序号)。
 *
 * ★ 与卡片、理财同一条纪律:这里只做**指代抽取**,不做订阅认定。
 *   抽取结果是一段文字(「爱奇艺」「那个云空间」),到底对应哪一笔订阅,
 *   由确定性引擎去流水与银行侧代扣协议里匹配。
 *   匹配不上时系统会如实说"没有找到" —— **绝不猜一个最像的**。
 *
 * ★ 为什么"猜"在这里格外危险:
 *   取消是一旦执行就改变合同关系的动作。猜错一笔,客户失去的是
 *   另一项他还在用的服务(可能是保险的保障)。宁可多问一句,不可猜一次。
 */
function extractSubscriptionRef(text: string): Intent["subscription"] {
  const s: NonNullable<Intent["subscription"]> = {};

  // 1) 协议号(用户明确给出时;模型与解析器都不编造)
  const idMatch = text.match(/(SUB_[A-Za-z0-9]{6,})/);
  if (idMatch?.[1]) s.subscriptionId = idMatch[1];

  // 2) 商户名:带引号的最可信,其次「爱奇艺会员」「腾讯视频」这类完整称呼
  const quoted = text.match(/[「"']([^」"']{2,20})[」"']/);
  if (quoted?.[1]) s.merchantName = quoted[1];

  if (!s.merchantName) {
    /**
     * ★ 商户名抽取的判据:用**取消动词/量词边界**切出名字,而不是拿整句去匹配。
     *   实测最典型的一句「把爱奇艺会员关了」:
     *     - 从"把/给/帮我把"之后开始 → 爱奇艺会员关了
     *     - 到第一个取消动词之前结束 → 爱奇艺会员
     *   这样抽出来的名字能直接命中"爱奇艺会员"这份协议。
     *
     *   不写成"必须匹配已知商户名单"的原因:客户签的下一份协议
     *   一定不在名单里(§10 坑 #8:白名单是 bug 温床)。
     */
    const named = text.match(
      /(?:把|将|给|帮我把|帮我将|我要|我想|要)\s*([\u4e00-\u9fa5A-Za-z0-9][\u4e00-\u9fa5A-Za-z0-9 ]{1,19}?)(?:会员|订阅|代扣|续费|包月)?\s*(?:关了|关掉|关闭|取消|取消掉|停掉|停了|退订|解约|解除|终止|不要了|别再扣)/,
    );
    if (named?.[1]) s.merchantName = named[1];
  }

  if (!s.merchantName) {
    // 「取消爱奇艺会员」「退订腾讯视频」
    const named2 = text.match(
      /(?:取消|关掉|关闭|停掉|退订|解约|解除|终止)\s*([\u4e00-\u9fa5A-Za-z0-9][\u4e00-\u9fa5A-Za-z0-9 ]{1,19}?)(?:的)?(?:会员|订阅|代扣|自动续费|续费|包月)/,
    );
    if (named2?.[1]) s.merchantName = named2[1];
  }

  if (!s.merchantName) {
    // 兜底:「爱奇艺会员多少钱」这类没有取消动词的查询
    const named3 = text.match(/([\u4e00-\u9fa5A-Za-z0-9][\u4e00-\u9fa5A-Za-z0-9 ]{1,17}(?:会员|订阅|代扣|云空间|云盘|网盘))/);
    if (named3?.[1]) s.merchantName = named3[1];
  }

  /**
   * ★ 抽出来的名字要**去掉首尾空格**。
   *
   *   实测踩到的一句:「把 iCloud 云空间关了」——
   *   Latin 商户名和中文之间通常有空格,允许空格参与匹配之后,
   *   尾巴上很容易带一个空格进到商户名里;而这个名字会一路进到
   *   审计台账与确认卡上(客户看到「iCloud 云空间 」以为系统打错了字)。
   */
  if (s.merchantName) s.merchantName = s.merchantName.trim();

  // 3) 位置指代(「第2个」「最后那个」)—— 只抽序号,不翻译
  const ordinalRefs = extractOrdinalRefs(text);
  if (ordinalRefs.length > 0) s.ordinalRefs = ordinalRefs;

  /**
   * ★ 抽取出来的"商户名"如果本身就是个序号或指代词,必须丢掉。
   *
   *   实测踩到:「取消第2个订阅」里的「第2」会被商户名正则抽出来 ——
   *   于是一个**位置指代**被当成了**商户名**。两者的解析路径完全不同:
   *   前者要在"刚刚展示过的清单"里取第 2 笔,后者要去银行目录里按名字匹配。
   *   混起来的结果是:系统拿"第2"去匹配商户,匹配不到,回一句"没有找到这笔订阅"——
   *   而客户明明就是照着系统给的编号念的。
   *
   *   判据:纯序号 / 序数词 / 指示代词一律不算商户名。
   */
  const ordinalish =
    /^(?:第|倒数第)?\s*[0-9０-９一二三四五六七八九十百两几]+\s*(?:个|笔|项|条|份|家|张)?$/;
  const deictic = /^(?:这|那|这个|那个|这些|那些|最后|最后一个|上面|前面|它|他)$/;
  if (s.merchantName && (ordinalish.test(s.merchantName) || deictic.test(s.merchantName))) {
    delete s.merchantName;
  }

  return Object.keys(s).length > 0 ? s : undefined;
}

/**
 * 抽取事件联动引用(场景六)。
 *
 * ★ 这里只抽三样东西:**客户怎么称呼这件事**、**有没有给预算**、**哪一类步骤**。
 *   日期不在这里解析 —— 它交给核心侧的确定性解析器(parseEventDateHint),
 *   因为"下个月15号"这种相对日期必须有**当前时间**与**日历**才谈得上正确;
 *   解析器里塞一份日历逻辑,等于把时间语义复制成两份,迟早对不上。
 *
 * ★ 商户名与序号都抽出来,但**都不在这里翻译**:序号要在"刚刚展示过的方案"里
 *   才有意义,商户要在商户目录里核 —— 两件事都必须去编排器里做。
 */
function extractEventRef(text: string): Intent["event"] {
  const e: NonNullable<Intent["event"]> = {};

  // 1) 客户对事件的称呼:优先取自述式("我结婚纪念日""我妈生日")
  //
  // ★ 不能用「往前抓 6 个汉字」这种贪心写法:实测「记一下11月15号是我结婚纪念日」
  //   会抽出「号是我结婚纪念日」—— 这个标题会一路进到事件清单、方案标题与审计台账,
  //   客户看到的是一句被剪断的句子。判据要落在**称谓本身**上:
  //   事件名词 + 紧邻它的修饰词(结婚/领证/相识…,或 妈/爸/老婆…)。
  const named =
    text.match(
      /((?:我)?(?:结婚|领证|相识|在一起|订婚)?(?:纪念日|周年)|(?:我)?(?:妈|爸|母亲|父亲|老婆|老公|孩子|家人|女儿|儿子|朋友)?(?:生日|寿辰)|发薪日|大额支出|大额开销|出游|旅游|旅行|度假|出行)/,
    )?.[1] ??
    text.match(/(纪念日|生日|寿辰|发薪日|周年|旅游|旅行|出游|出行)/)?.[1];
  if (named) {
    // 「我结婚纪念日」→「结婚纪念日」;但「我妈生日」要保留「我」(去掉就指向不明了)
    const trimmed = /^我(?!妈|爸|母亲|父亲|老婆|老公|孩子|家人|女儿|儿子|朋友)/.test(named) ? named.slice(1) : named;
    e.keyword = trimmed.trim();
  }

  // 2) 预算:客户明确说了"预算/花 N 元"时才算数(没说就由引擎按余额估算)
  const budget = text.match(/(?:预算|花|准备)\s*(?:大概|大约|差不多)?\s*([0-9零一二两三四五六七八九十百千万]+)\s*(?:块|元|块钱)?/);
  if (budget?.[1]) {
    const n = Number(budget[1]);
    if (Number.isFinite(n) && n > 0) e.budget = n;
  }

  // 3) 哪一类步骤:资金 / 外部
  if (/(外部|外部服务|商户|订购|下单|订花|蛋糕|餐厅|酒店)/.test(text)) e.domain = "external";
  else if (/(资金操作|预留|锁定|定时任务|留出来|留出)/.test(text)) e.domain = "fund";

  // 4) 资金步骤的方式:明确说"取消/解开/解锁"时才是 release
  //
  // ★ 中间允许插入指代词(「取消**刚才那个**预留」),也允许语序反过来
  //   (「把预留解开」):这是最自然的两种口语。少了它们,系统会把"解开"
  //   读成"再锁一次" —— 确认卡上还写着"预留",客户点完确认,钱反而被锁住,
  //   或者干脆听不懂。方向读反是这里最严重的错误。
  //   判据与编排器的"方向判据"共用同一份实现(intent/eventWording.ts)。
  if (isEventReleaseSpoken(text)) e.mode = "release";
  else if (/(定时|到点|自动转|发薪后|到账后)/.test(text)) e.mode = "schedule";

  // 5) 序号(「第2步」)—— 只在刚刚展示过的方案里成立
  const stepOrdinal = text.match(/第\s*([0-9一二三四五六七八九十]+)\s*步/);
  if (stepOrdinal) {
    const n = chineseNumeralToInt(stepOrdinal[1]!);
    if (n > 0) e.ordinalRefs = [{ kind: "indices", indices: [n], n }];
  }

  return Object.keys(e).length > 0 ? e : undefined;
}

/** 中文数字 → 整数(只处理"第N步"这种 1–99 的范围,够用且不引入猜测) */
function chineseNumeralToInt(raw: string): number {
  if (/^[0-9]+$/.test(raw)) return Number(raw);
  const digits: Record<string, number> = { 一: 1, 二: 2, 两: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9 };
  if (raw === "十") return 10;
  const ten = /^十(.)$/.exec(raw);
  if (ten) return 10 + (digits[ten[1]!] ?? 0);
  const tens = /^(.)十(.)?$/.exec(raw);
  if (tens) return (digits[tens[1]!] ?? 0) * 10 + (tens[2] ? (digits[tens[2]] ?? 0) : 0);
  return digits[raw] ?? 0;
}

/**
 * 用户是否给出了一个**具体的**目标额度(用于区分"提额资格查询"与"提额申请")。
 *
 * ★ 这个区分很关键:「额度太低能不能提额」问的是**资格**,
 *   而「帮我把额度提到 5 万」才是**申请**。
 *   如果前者也走申请流程,客户会莫名收到一张"申请已提交"的回执 ——
 *   而他连自己够不够格都还不知道。
 */
function asksLimitAmount(text: string): boolean {
  // 明确的目标额度:提到 / 涨到 / 申请到 + 数字
  if (/(提到|涨到|调到|申请到|提额到)\s*[0-9零一二两三四五六七八九十百千万]/.test(text)) return true;
  // 「申请提额 5 万」这类
  if (/(申请|提交).{0,6}(提额|调额|额度).{0,6}[0-9零一二两三四五六七八九十百千万]/.test(text)) return true;
  // 「提额到 5 万」
  if (/提额\s*到\s*[0-9零一二两三四五六七八九十百千万]/.test(text)) return true;
  return false;
}

/**
 * 从查询类表达中推断时间范围。
 *
 * 说明:分类的识别放在编排器里做(orchestrator 的 buildAnalysisQuery)——
 * 因为那里有演示数据使用的规范分类名,而解析器不该硬编码业务数据。
 * 这里只负责时间范围。
 */function extractQueryParams(text: string, now: number): Intent["query"] {
  const q: NonNullable<Intent["query"]> = {};

  const day = 24 * 3600 * 1000;
  if (/这个月|本月/.test(text)) {
    const d = new Date(now);
    q.fromIso = new Date(d.getFullYear(), d.getMonth(), 1).toISOString();
  } else if (/上个月|上月/.test(text)) {
    const d = new Date(now);
    q.fromIso = new Date(d.getFullYear(), d.getMonth() - 1, 1).toISOString();
    q.toIso = new Date(d.getFullYear(), d.getMonth(), 1).toISOString();
  } else if (/这周|本周/.test(text)) {
    q.fromIso = new Date(now - 7 * day).toISOString();
  } else if (/上周/.test(text)) {
    q.fromIso = new Date(now - 14 * day).toISOString();
    q.toIso = new Date(now - 7 * day).toISOString();
  } else if (/今年|本年度|年度|全年/.test(text)) {
    const d = new Date(now);
    q.fromIso = new Date(d.getFullYear(), 0, 1).toISOString();
  } else if (/去年|上一年/.test(text)) {
    const d = new Date(now);
    q.fromIso = new Date(d.getFullYear() - 1, 0, 1).toISOString();
    q.toIso = new Date(d.getFullYear(), 0, 1).toISOString();
  } else if (/最近三天|近三天/.test(text)) {
    q.fromIso = new Date(now - 3 * day).toISOString();
  } else if (/最近一周|近一周|最近7天/.test(text)) {
    q.fromIso = new Date(now - 7 * day).toISOString();
  }

  return Object.keys(q).length > 0 ? q : undefined;
}

// ============================================================================
// 抽取器
// ============================================================================

/** 中文数字 → 阿拉伯数字 */
const CN_DIGITS: Record<string, number> = {
  零: 0, 一: 1, 二: 2, 两: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9, 十: 10,
};

function cnToNumber(s: string): number | null {
  if (!s) return null;
  if (/^\d+(\.\d+)?$/.test(s)) return Number(s);

  const chars = [...s];
  let total = 0;
  let section = 0;
  let hasAny = false;
  /** 最近一次出现的数量级(用于"五万三"= 53000 这类的尾数补全) */
  let lastMagnitude = 0;
  /** 尾数:紧跟在数量级后面连续出现的数字,如"三" */
  let tailDigits: number[] = [];

  for (const ch of chars) {
    const magnitude =
      ch === "十" ? 10 : ch === "百" ? 100 : ch === "千" ? 1000 : ch === "万" ? 10_000 : ch === "亿" ? 100_000_000 : 0;

    if (magnitude > 0) {
      // 先把待处理的数字位结算掉
      if (tailDigits.length > 0) {
        let v = 0;
        for (const d of tailDigits) v = v * 10 + d;
        section += v;
        tailDigits = [];
      }

      if (ch === "十") section = section === 0 ? 10 : section * 10;
      else if (ch === "百") section = (section === 0 ? 1 : section) * 100;
      else if (ch === "千") section = (section === 0 ? 1 : section) * 1000;
      else {
        // 万 / 亿:结算当前 section
        total = (total + (section === 0 ? 1 : section)) * magnitude;
        section = 0;
      }
      lastMagnitude = magnitude;
      hasAny = true;
    } else if (CN_DIGITS[ch] != null) {
      tailDigits.push(CN_DIGITS[ch]!);
      hasAny = true;
    } else {
      return null;
    }
  }

  // 收尾结算
  if (tailDigits.length > 0) {
    let v = 0;
    for (const d of tailDigits) v = v * 10 + d;
    if (lastMagnitude > 1) {
      // ★ 数量级之后的数字是"尾数":按下一级数量级折算
      //   "三千二" → 3000 + 2×100 = 3200;"五万三" → 50000 + 3×1000 = 53000
      section += v * (lastMagnitude / 10);
    } else {
      section += v;
    }
  }

  return hasAny ? total + section : null;
}

/**
 * 从文本中剥离"非金额"的数字表达。
 *
 * ★ 必要性:离线解析用正则抽取数字,而中文里数字大量出现在非金额语境:
 *   "每月1号"(日期)、"尾号1234"(账号)、"13800138000"(手机号)、"下午3点"(时间)。
 *   不先剥离就会把"每月1号给房东转5800"解析成金额 1 —— 这是危险错误:
 *   用户以为转 5800,系统准备转 1 元。
 *   大模型不会犯这个错,所以这条规则的价值在于让离线降级路径同样可靠。
 */
function stripNonAmountNumbers(text: string): string {
  let s = text;
  /**
   * ★ 顺序要紧:**完整日期必须先剥**,再剥"数字 + 号/日"。
   *   反过来(先剥 `\d{1,2}[号日]`)会把「2026年1月1日」啃成「2026年1月」,
   *   日期正则从此匹配不上,剩下的 2026 就被当成金额 —— 实测确实抽出 2026 元。
   *   与 core 层 `extractAmountFromText` 同口径(两份解析器不得互相矛盾)。
   */
  s = s.replace(/\d{4}\s*[-/年]\s*\d{1,2}\s*[-/月]\s*\d{1,2}\s*[日号]?/g, " ");
  // 每月/每年/每周 + 数字 + 号/日
  s = s.replace(/(每月|每年|每周|每天|每月)\s*\d{1,2}\s*[号日]/g, " ");
  s = s.replace(/\d{1,2}\s*[号日]\s*(?=[^\d]|$)/g, " ");
  // 手机号(11 位)
  s = s.replace(/1[3-9]\d{9}/g, " ");
  // 尾号/账号
  s = s.replace(/(尾号|后四位|末尾|账号|卡号)\s*\d+/g, " ");
  // ★ 序号/位置指代:「第4个」「第 3 只」「前两个」—— 这是列表编号,不是金额。
  //   实测踩到:「买第4个5万」被抽出金额 4 元(来自"第4个"的"4"),
  //   而真正的 5 万被漏掉。位置指代与金额在句式里并存时,
  //   必须先剔掉序号,再抽金额,否则金额永远取错。
  s = s.replace(/第\s*\d{1,2}\s*[个只支款种]?/g, " ");
  s = s.replace(/前\s*\d{1,2}\s*[个只支款种]?/g, " ");
  // 时间点
  s = s.replace(/(上午|下午|中午|晚上|凌晨)?\s*\d{1,2}\s*[点时](\s*\d{1,2}\s*[分])?/g, " ");
  return s;
}

export function extractAmount(text: string): Intent["amount"] | null {
  const searchText = stripNonAmountNumbers(text);

  // 1) 阿拉伯数字 + 单位:500、1,200.50、5万、1.5k、3千、5万3
  const arabic = searchText.match(/(\d[\d,]*(?:\.\d+)?)\s*(万|千|百|亿|k|K|w|W)?\s*(?:块|元|块钱|人民币|rmb|RMB)?/);
  if (arabic && arabic[1]) {
    let value = Number(arabic[1].replace(/,/g, ""));
    const unit = arabic[2];
    let unitMultiplier = 1;
    if (unit === "万" || unit === "w" || unit === "W") unitMultiplier = 10_000;
    else if (unit === "千" || unit === "k" || unit === "K") unitMultiplier = 1_000;
    else if (unit === "百") unitMultiplier = 100;
    else if (unit === "亿") unitMultiplier = 100_000_000;
    value *= unitMultiplier;

    // ★ 中文口语常用省略式:"5万3" = 53000,"3千2" = 3200。
    //   单位后面的尾数按下一级数量级折算(万→千,千→百,百→十)。
    //   必须确认尾数后面不再跟数量级字,否则"5万3千"会被重复计算。
    if (unitMultiplier >= 100) {
      const tailMatch = searchText
        .slice((arabic.index ?? 0) + arabic[0].length)
        .match(/^(\d)(?![零一二三四五六七八九十百千万亿\d])/);
      if (tailMatch?.[1]) {
        value += Number(tailMatch[1]) * (unitMultiplier / 10);
      }
    }

    // 避免把长数字串误认为金额:长度 > 7 位且无单位时忽略
    if (/^\d{8,}$/.test(arabic[1].replace(/,/g, "")) && !unit) return null;
    if (value > 0) return { value, currency: "CNY", raw: arabic[0].trim(), derived: false };
  }

  // 2) 中文数字 + 单位:五百、三千、一万、五万三、三千二
  //    尾数折算("三千二"=3200)已由 cnToNumber 内部处理,此处不再二次拼接。
  const cn = searchText.match(/([零一二两三四五六七八九十百千万亿]+)\s*(?:块|元|块钱)?/);
  if (cn && cn[1]) {
    // ★ 排除"一"作副词的情况 —— 这是一个真实踩到的 bug:
    //   「帮我弄一下那个」被解析出金额 1(来自"一下"的"一"),
    //   于是系统认为"金额已经有了",只追问收款人,还回显"¥1";
    //   同时让"这句话没有任何业务线索"的判断失效(因为看起来有金额了),
    //   本该回复"我不确定你要办哪件事"的含糊请求,被当成了一笔 1 元转账。
    //   判据:"一/两/几"这类单字数字后面紧跟的是副词性字词时,它不是金额。
    const value = cnToNumber(cn[1]);
    const after = searchText.slice((cn.index ?? 0) + cn[0].length);
    const adverbFollow = /^(下|些|点|会儿|下子|直|样|起|块|般|边|定|向|再|阵|览|系列|致|同)/.test(after);
    const isSingleAdverbNumeral = cn[1].length === 1 && /[一两几]/.test(cn[1]) && !/[百千万亿]/.test(cn[1]);
    if (isSingleAdverbNumeral && adverbFollow) {
      // 不是金额:继续尝试在同一句里找别的数字,找不到就返回 null
      const rest = searchText.slice((cn.index ?? 0) + cn[0].length);
      const later = rest.match(/([零一二两三四五六七八九十百千万亿]+)\s*(?:块|元|块钱)?/);
      if (!later?.[1]) return null;
      const laterValue = cnToNumber(later[1]);
      if (laterValue != null && laterValue > 0) {
        return { value: laterValue, currency: "CNY", raw: later[0].trim(), derived: false };
      }
      return null;
    }
    if (value != null && value > 0) {
      return { value, currency: "CNY", raw: cn[0].trim(), derived: false };
    }
  }

  return null;
}

const ACCOUNT_TYPE_HINTS: Array<{ re: RegExp; type: "current" | "savings" | "credit" | "ewallet" }> = [
  { re: /信用卡/, type: "credit" },
  { re: /储蓄卡|储蓄账户|定期/, type: "savings" },
  { re: /零钱|钱包|电子账户/, type: "ewallet" },
  { re: /工资卡|活期|主卡/, type: "current" },
];

function extractFromAccount(text: string): Intent["fromAccount"] | null {
  // 尾号 1234 / 后四位 1234
  const tail = text.match(/(?:尾号|后四位|末尾)\s*(\d{3,4})/);
  if (tail) return { raw: tail[0], accountId: undefined };
  for (const h of ACCOUNT_TYPE_HINTS) {
    if (h.re.test(text)) return { raw: text.match(h.re)![0], typeHint: h.type };
  }
  return null;
}

/** 转账目标动词前缀,用于定位收款人主体 */
const PAYEE_PREFIXES = ["转账给", "转钱给", "帮我还给", "还给", "转给", "打给", "汇给", "给", "向"];

/**
 * 按长度降序排列的前缀列表。
 *
 * ★ 必须长前缀优先,否则「那转给张伟1500」会被「给」抢先匹配,
 *   得到 rest = "张伟1500" 而匹配失败(用户看到"请问要转给谁")。
 *   这是一个纯粹的顺序 bug,但表现是"系统听不懂人话"。
 */
const PAYEE_PREFIXES_SORTED = [...PAYEE_PREFIXES].sort((a, b) => b.length - a.length);

/**
 * 延续词:出现在动词前时表示"再来一笔"。
 *
 * ★ 注意:这里只包含"后面直接跟收款人"以外的情形。
 *   "给/向"是**介词**,不是动作动词 —— "再给房东转5800"里的"给"后面
 *   跟的是收款人房东,不能因为前面有"再"就跳过它。
 *   早期把"给/向"也放进这个集合,导致"再给房东转5800"去匹配后面的"转",
 *   而"转"后面是金额,于是取不到收款人,系统错误地继承了上一条的收款人
 *   (该转给陈建国却转给了王秀兰 —— 这是一个会转错人的 bug)。
 */
const CONTINUATION_CHARS = new Set(["再", "还", "又", "也", "顺", "另"]);

/**
 * 从"动词之后"的片段里取出姓名或昵称。
 *
 * 规则(按顺序):
 *   1. 去掉开头的引号(用户可能说「给"老妈"转500」)
 *   2. 逐字符收集中文,直到遇到**终止符**:
 *      · 标点与空白     —— 天然边界
 *      · 数字           —— 金额紧跟姓名("给张伟1500")
 *      · 动作动词       —— 姓名后接动词("给老王转500",必须在此停下)
 *      · 单位词(元/块) —— 姓名后接单位属于异常,但作为边界更安全
 *   3. 长度限制 2–6 字;不足 2 字视为取不到
 *
 * 终止符里必须包含动作动词,否则"给老王转500"会取到"老王转"。
 * 但也不能把动词当**唯一**边界 —— 实测确认过两种失败模式都出现过。
 */
function takePayeeToken(rest: string): string | null {
  // ★ 停止集只包含**动作动词**与**单位词**,不包含介词。
  //   踩过的坑:"给/向/跟/和"曾被放进停止集,而它们正是"取姓名"的入口 ——
  //   对于"再给房东转5800",前缀扫描会先匹配到"转"(前面的"再"触发跳过),
  //   之后匹配到"给",此时 rest = "房东转5800" 没问题;
  //   但对"给"之前还有字的句子,rest 可能以"给"开头(如代理场景),
  //   于是 token 为空,而**空的 token 会让后面的前缀也没机会尝试**。
  //   介词不是边界,把它们移出停止集后,取姓名只受动作动词约束。
  const STOP_CHARS = new Set(["转", "打", "汇", "付", "交", "缴", "元", "块"]);
  const STOP_LEADING = new Set(["“", "”", "「", "」", "『", "』", '"', "'"]);

  let start = 0;
  while (start < rest.length && STOP_LEADING.has(rest[start]!)) start++;

  let token = "";
  for (let i = start; i < rest.length && token.length < 6; i++) {
    const ch = rest[i]!;
    if (/[\u4e00-\u9fa5]/.test(ch) && !STOP_CHARS.has(ch)) {
      token += ch;
      continue;
    }
    break; // 遇到标点/数字/空白/动作动词 → 终止
  }

  return token.length >= 2 ? token : null;
}

export function extractPayee(text: string): Intent["payee"] | null {
  // ---- 手机号 ----
  const phone = text.match(/1[3-9]\d{9}/);
  if (phone) {
    return { by: "phone", raw: phone[0], phone: phone[0] };
  }
  // 手机号后四位 + 前缀
  const phoneTail = text.match(/(?:手机号|号码|尾号)\s*(\d{4})\b/);
  if (phoneTail) {
    return { by: "phone", raw: phoneTail[0], phone: phoneTail[1]! };
  }

  // ---- 账号 ----
  const acc = text.match(/(?:账号|卡号)\s*(\d{8,})/);
  if (acc) return { by: "account_no", raw: acc[0], accountNo: acc[1]! };

  // ---- 历史指代(必须带明确的历史线索词,否则会误吞正常姓名) ----
  // ★ 曾经的 bug:宽松的 /给([^\s,,。]{1,8})/ 会把"直接给王强转50万"里的
  //   "王强转50万"整段当成指代对象,导致收款人解析失败。
  //   修正:只在出现"上次/上个月/之前/还是/照旧"等线索词时才走历史解析,
  //   且捕获组遇到动作动词(转/打/汇/付)立即中断。
  const historyPatterns = [
    /(上次|上回)(?:那个|那位|那家)?([\u4e00-\u9fa5]{1,6})?/,
    /(上个月|上月)(?:那个|那位|那家)?([\u4e00-\u9fa5]{1,6})?/,
    /(之前)(?:那个|那位|那家)?([\u4e00-\u9fa5]{1,6})?/,
  ];
  for (const p of historyPatterns) {
    const m = text.match(p);
    if (m) {
      return {
        by: "history",
        raw: m[0],
        historyHint: {
          description: m[2] ? `用户提到"${m[2]}"相关的历史收款人` : `用户提到${m[1]}的转账对象`,
        },
      };
    }
  }
  const idiom = text.match(/还是(?:那个|老样子|按上次)|照旧|老规矩|和上次一样/);
  if (idiom) {
    return {
      by: "history",
      raw: idiom[0],
      historyHint: { description: "沿用上次转账的收款人" },
    };
  }

  // ---- 姓名:动词 + 姓名/昵称 ----
  // ★ 跳过规则只对**动作动词**生效,绝不对**介词**生效。
  //   这条区分是必须的,因为中文有两种看似相同、实则相反的句式:
  //     · "再转500"       —— "再"修饰动词"转",整句**没有**收款人 → 应跳过
  //     · "再给房东转5800" —— "再"修饰的是"给房东转"这件事,"给"后面**有**收款人
  //   若对"给"也应用跳过规则,"给"会被跳过,而它恰恰是这个句子中
  //   唯一能定位收款人的入口(其余前缀都不匹配),
  //   系统便判定"用户没说收款人",错误地继承了上一条的收款人 ——
  //   实测表现:该转给陈建国,却转给了王秀兰。这是一个会转错人的 bug。
  const PREPOSITIONS = new Set(["给", "向"]);
  for (const prefix of PAYEE_PREFIXES_SORTED) {
    let idx = text.indexOf(prefix);
    while (idx >= 0) {
      const before: string = idx > 0 ? (text[idx - 1] ?? "") : "";
      // 介词不参与跳过:它后面必定跟收款人
      if (PREPOSITIONS.has(prefix) || !CONTINUATION_CHARS.has(before)) break;
      idx = text.indexOf(prefix, idx + 1);
    }
    if (idx < 0) continue;
    const rest = text.slice(idx + prefix.length).trim();
    // ★ 用字符遍历取姓名,不用正则。原因:
    //   姓名捕获组 {2,4} 是贪婪的,配后括断言时会为了"凑够边界"而多吃一个动词 ——
    //   "给老王转500" 取 2 字"老王"后下一字符是"转"(不满足断言),正则便扩到
    //   "老王转",此时下一字符是"5"(满足 \d),于是"老王转"被当成人名。
    //   实测表现为:用户说"给老王转500",系统答"名单里没有『老王转』"。
    //   字符遍历可以精确表达"遇到动作动词就停",不存在这类歧义。
    const token = takePayeeToken(rest);
    if (!token) continue;

    // ★ 排除"假人名":延续词开头的片段("再转500"里的"再转")。
    //   这类片段的语义是"再来一笔",本身不含收款人,应当在
    //   payee 缺失时由编排器从上下文继承上一条的收款人。
    //
    //   ★ 关键:这里必须 **continue(跳过继续试下一个前缀),不能 return null**。
    //   原因:前缀扫描是"短动词优先"的 —— "再给房东转5800"会先匹配到"转",
    //   取出假人名"再转";如果此时直接 return null,后面更精确的介词"给"
    //   就永远没机会尝试,于是这句明明说了"房东"却被判为没说收款人,
    //   系统错误地继承了上一条的收款人(该转给陈建国却转给了王秀兰)。
    //   跳过假人名、继续尝试其余前缀,才能让"给"命中"房东"。
    if (CONTINUATION_CHARS.has(token[0]!) && token.length <= 3) {
      continue;
    }

    // ★ 无法从语法上区分"真名"与"昵称"(如「老妈」既是 2 字中文也可能是昵称)。
    //   因此这里统一按 alias 返回,由实体消歧器做权威判定:
    //   实体消歧器会先精确匹配别名表,未命中再降级为姓名搜索(resolveByAlias 已实现该降级)。
    //   这样「老妈」命中别名,「王秀兰」则走姓名匹配,两种情况都能正确收敛。
    return { by: "alias", raw: token, alias: token };
  }

  // ---- 情感/语境线索:「房东催租了」----
  // ★ 隐含意图:用户说"房东催租了",字面上没有"转账"两个字,
  //   但语境明确指向"该给房东付房租了"。识别出对象,金额留待澄清。
  if (/(催|要|该给|该付|到期|欠|还差|别忘了给)/.test(text)) {
    const who = text.match(/^([\u4e00-\u9fa5]{2,4})/);
    if (who?.[1] && !/^(我|你|他|她|这个|那个)/.test(who[1])) {
      return { by: "alias", raw: who[1], alias: who[1] };
    }
  }

  // ---- 单独的姓名(如"王秀兰 500"、"老妈 2000") ----
  // 注意这里的终止条件必须宽松:后面可能直接跟数字(金额),
  // 早期版本的 (?=[\s,,。]|$) 会因为"老妈2000"没有空格而匹配失败。
  const lone = text.match(/^\s*([\u4e00-\u9fa5]{2,4})(?=$|[\s,,。]|\d)/);
  if (lone?.[1] && !/^(帮我|我要|我想|查询|看看|给我|这个|那个|昨天|今天|明天)/.test(lone[1])) {
    return { by: "alias", raw: lone[1], alias: lone[1] };
  }

  return null;
}

/**
 * 剥掉产品名前粘连的量词/动词/介词/数词。
 *
 * 例:「块科技成长精选」→「科技成长精选」;「把科技成长精选」→「科技成长精选」;
 *     「1万块纯债添利」→「纯债添利」。
 *
 * ★ 只剥离**前缀**里的功能词,绝不动中间与结尾的字 ——
 *   产品名本身可能含"利""精选""增利"这类看不出是功能词的字,
 *   过度剥离会把「纯债添利」削成「纯债添」,反而查不到。
 */
function stripProductNamePrefix(name: string): string {
  // 从左往右反复剥离:数词、量词、动词、介词、代词、标点
  const STRIP = /^(?:[0-9０-９.,]+|[零一二两三四五六七八九十百千万亿]+|[块元万元钱份]|[买申购投建仓入配置点要想要帮我把将给向用花就都全再次还也]|[那个这个的得地]|[「」"'\s])/;
  let out = name;
  for (let i = 0; i < 8; i++) {
    const next = out.replace(STRIP, "");
    if (next === out) break;
    out = next;
  }
  return out;
}

function extractMemo(text: string): string | undefined {
  const m = text.match(/(?:备注|附言|留言)\s*(?:写|填|是|为)?\s*["「"']?([^"」"'’]{1,50})["」"'’]?/);
  if (m && m[1]) return m[1].trim();
  // 用途类表述转备注
  const purpose = text.match(/(?:这是|算是|当做|作为)\s*([^,,。]{2,20})/);
  if (purpose && purpose[1]) return purpose[1].trim();
  return undefined;
}

function extractSchedule(text: string, now: number): Intent["schedule"] | undefined {
  const isScheduled = /(每月|每周|每天|定时|自动|定期|下个月|明天|后天|下周|每月\d+号)/.test(text);
  if (!isScheduled) return undefined;

  const raw = (text.match(/(每月|每周|每天|定时|自动|定期|下个月|明天|后天|下周)[^\s,,。]{0,6}/) ?? [""])[0];

  let frequency: "once" | "daily" | "weekly" | "monthly" = "once";
  if (/每月|下个月/.test(text)) frequency = "monthly";
  else if (/每周|下周/.test(text)) frequency = "weekly";
  else if (/每天|每日/.test(text)) frequency = "daily";

  const firstRunAt = computeFirstRun(text, now, frequency);

  return {
    isScheduled: true,
    firstRunAtIso: new Date(firstRunAt).toISOString(),
    rawExpression: raw,
    recurrence: { frequency, interval: 1 },
    onInsufficientFunds: "notify_and_skip",
    preExecutionReminder: true,
  };
}

/** 算出首次执行时间(★ 周期本身由调用方从原话判定,所以 `_frequency` 只占位不参与计算) */
function computeFirstRun(text: string, now: number, _frequency: string): number {
  const d = new Date(now);

  // 每月 N 号
  const dayMatch = text.match(/每月\s*(\d{1,2})\s*[号日]/);
  if (dayMatch) {
    const target = Number(dayMatch[1]);
    const candidate = new Date(d.getFullYear(), d.getMonth(), target, 9, 0, 0, 0);
    if (candidate.getTime() <= now) candidate.setMonth(candidate.getMonth() + 1);
    return candidate.getTime();
  }

  // 下个月
  if (/下个月|下月/.test(text)) {
    const candidate = new Date(d.getFullYear(), d.getMonth() + 1, 1, 9, 0, 0, 0);
    return candidate.getTime();
  }

  // 明天 / 后天
  if (/明天/.test(text)) {
    const c = new Date(d);
    c.setDate(c.getDate() + 1);
    c.setHours(9, 0, 0, 0);
    return c.getTime();
  }
  if (/后天/.test(text)) {
    const c = new Date(d);
    c.setDate(c.getDate() + 2);
    c.setHours(9, 0, 0, 0);
    return c.getTime();
  }

  // 每周 X
  const weekMatch = text.match(/每周([一二三四五六日天])/);
  if (weekMatch) {
    const map: Record<string, number> = { 一: 1, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6, 日: 0, 天: 0 };
    const targetDow = map[weekMatch[1]!] ?? 1;
    const c = new Date(d);
    const diff = (targetDow - c.getDay() + 7) % 7 || 7;
    c.setDate(c.getDate() + diff);
    c.setHours(9, 0, 0, 0);
    return c.getTime();
  }

  // 默认:次日 9 点
  const c = new Date(d);
  c.setDate(c.getDate() + 1);
  c.setHours(9, 0, 0, 0);
  return c.getTime();
}

/** 参与人姓名中需要剔除的"自己"指代 —— 发起人不是分摊对象 */
const SELF_TOKENS = ["我", "本人", "咱们", "我们", "自己", "咱"];

function extractParticipants(text: string): Array<{ displayName: string; phone?: string }> {
  const out: Array<{ displayName: string; phone?: string }> = [];

  // 先剔除"我/我们"等自称,以及"帮我跟/和我一起"这类连接成分。
  // 否则"帮我跟李明、王秀兰 AA"会把"帮我"当成一个参与人。
  const cleaned = text
    .replace(/(帮我|帮忙|替我|替我)/g, "")
    .replace(/(我|我们|咱们|咱)(跟|和|与|同)/g, "")
    .replace(/(跟|和|与|同)(?=[\u4e00-\u9fa5]{2,4}[、,和及])/g, "")
    // ★ 关键:必须**先**把"一起/一块/一同/吃的"这类共担语气词删掉,再匹配姓名列表。
    //   否则贪婪的 {2,4} 会把"王秀兰一起"切成"王秀兰一" ——
    //   实测中参与人真的变成了「王秀兰一」,而且这个错误名字会一路进入
    //   AA 收款卡片、收款请求与对账记录,属于会留下错误数据的 bug。
    .replace(/(一起|一块|一同|一起的|同时|共同)/g, "")
    .replace(/(吃的|吃饭|聚餐|分摊|均摊|拼单|AA|aa)/g, "");

  // 顿号/逗号/和/及 分隔的姓名列表
  const listMatch = cleaned.match(/([\u4e00-\u9fa5]{2,4}(?:[、,和及][\u4e00-\u9fa5]{2,4})+)/);
  if (listMatch && listMatch[1]) {
    for (const raw of listMatch[1].split(/[、,和及]/)) {
      // 二次兜底:去掉残留的语气词/连接词尾巴
      const name = raw.trim().replace(/(一起|一块|一同|等|都|也|还有|的)+$/g, "");
      if (name.length < 2) continue;
      if (SELF_TOKENS.includes(name)) continue;
      // 剔除仍带自称前缀的残余(如"我跟")
      const stripped = name.replace(/^(我|咱|我们|咱们)(跟|和|与|同)?/, "");
      const finalName = stripped.length >= 2 ? stripped : name;
      if (SELF_TOKENS.includes(finalName)) continue;
      if (!out.some((o) => o.displayName === finalName)) out.push({ displayName: finalName });
    }
  }

  // 手机号列表
  const phones = cleaned.match(/1[3-9]\d{9}/g) ?? [];
  for (const p of phones) {
    if (!out.some((o) => o.phone === p)) out.push({ displayName: `尾号${p.slice(-4)}`, phone: p });
  }

  return out;
}

function extractCollectionTitle(text: string): string {
  // 事由关键词后允许跟"我垫了/一共/总共"等词,再遇到逗号或数字即停
  const m = text.match(/(聚餐|吃饭|团建|旅行|旅游|打车|外卖|拼单|看电影|KTV|唱歌|下午茶|年会|生日)[^\s,,。\d]{0,8}/);
  if (m) return m[0].replace(/(我|咱|我们)(垫了?|付了?|出了?)/g, "").trim();
  if (/打车/.test(text)) return "打车费用";
  if (/团建/.test(text)) return "团建费用";
  if (/旅行|旅游/.test(text)) return "旅行费用";
  return "分摊收款";
}

function computeConfidence(input: {
  payee: Intent["payee"] | null;
  amount: Intent["amount"] | null;
  action: string;
  text: string;
}): number {
  let c = 0.5;
  if (input.payee) c += 0.2;
  if (input.amount) c += 0.2;
  // 明确的转账动词 → 提高置信度
  if (/转(账|给)|打给|汇给/.test(input.text)) c += 0.1;
  // 极短输入(如"转500")缺少收款人 → 降低
  if (input.text.length < 6) c -= 0.2;
  return Math.max(0, Math.min(1, c));
}

function buildRestatement(input: {
  action: string;
  payee: Intent["payee"] | null;
  amount: Intent["amount"] | null;
  text: string;
}): string {
  const payeeDesc = input.payee
    ? input.payee.by === "phone"
      ? `手机号 ${input.payee.phone}`
      : input.payee.by === "history"
        ? input.payee.raw
        : (input.payee.name ?? input.payee.alias ?? input.payee.raw)
    : "未指定的收款人";
  const amountDesc = input.amount ? `${input.amount.value} 元` : "未指定的金额";

  switch (input.action) {
    case "transfer.send":
      return `用户想要向 ${payeeDesc} 转账 ${amountDesc}`;
    case "transfer.schedule":
      return `用户想要设置一笔向 ${payeeDesc} 的定时转账,金额 ${amountDesc}`;
    case "transfer.cancel":
      return "用户想要撤销一笔转账";
    case "collection.create":
      return `用户想要发起一笔 AA 收款,总额 ${amountDesc}`;
    case "account.balance":
      return "用户想要查询账户余额";
    case "account.transactions":
      return "用户想要查询交易流水";
    // ---- 理财(场景三)----
    case "wealth.list_products":
      return input.amount
        ? `用户想用大约 ${amountDesc} 了解/挑选理财产品`
        : "用户想了解有哪些理财产品";
    case "wealth.product_detail":
      return `用户想了解某只理财产品的详情:${input.text.slice(0, 30)}`;
    case "wealth.compare":
      return "用户想对比两只理财产品的收益与风险";
    case "wealth.risk_assess":
      return "用户想做风险承受能力测评 / 了解自己能买什么风险等级的产品";
    case "wealth.purchase":
      return `用户想申购理财产品,金额 ${amountDesc}`;
    case "wealth.redeem":
      return "用户想赎回持有中的理财产品";
    case "wealth.holdings":
      return "用户想查询理财持仓与收益";
    case "wealth.sign_consent":
      return "用户想签署风险不匹配确认书";
    // ---- 跨场景事件联动(新场景)----
    //
    // ★ 复述里必须带上"只出方案/只办一步"的意思:复述是审计的一部分,
    //   而这几句话的口径差别正是本场景最要紧的地方 ——
    //   「帮我规划」与「按方案执行」在复述里必须一眼能分开。
    case "cross_scene_event_planning":
      return `用户有一个关键事件想规划(仅生成方案,不执行任何步骤):${input.text.slice(0, 40)}`;
    case "event.list":
      return "用户想了解已登记的关键事件与可用的事件触发器";
    case "event.register":
      return `用户想登记一个关键事件:${input.text.slice(0, 40)}`;
    case "event.fund_step":
      return `用户想执行方案里的资金操作步骤(需确认):${input.text.slice(0, 40)}`;
    case "event.external_step":
      return `用户想执行方案里的外部服务操作步骤(需强验证):${input.text.slice(0, 40)}`;
    default:
      return `用户请求:${input.text.slice(0, 60)}`;
  }
}
