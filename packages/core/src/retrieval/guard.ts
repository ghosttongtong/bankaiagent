/**
 * 置信度判定、拒答、数字类问题识别。
 *
 * ★ 这个文件存在的理由只有一句:**宁可拒答,不可猜答**。
 *   制度问答最坏的失败不是"答不上来",而是"答了一条看起来很像、
 *   但其实不适用的条款" —— 客户会照着它去办事,然后把责任算在银行头上。
 *   所以接受条件是三条**同时**满足(32 文档 §4.3):
 *     ① 最高分够高;② 查询词覆盖率够高;③ 与第二名拉开差距。
 *
 * ★ 阈值是初值,必须用评测集校准(见 tools/verify-rag.mjs 与 32 文档 §7.2)。
 *   当前值:MIN_SCORE = 2.0 / MIN_COVERAGE = 0.5 / MIN_GAP_RATIO = 1.15。
 */

/** 接受门槛:最高分 */
export const MIN_SCORE = 2.0;
/** 接受门槛:查询词覆盖率 */
export const MIN_COVERAGE = 0.5;
/**
 * 接受门槛:与第二名的比值(避免"两条都像")。
 *
 * ★ 1.15 → 1.10 是评测校准的结果(32 文档 §7.2):
 *   初值 1.15 会把一条**明显更好、但第二名也不差**的正确命中挡掉 ——
 *   典型是「单笔多少钱以上要人脸」:正确答案的标题就是「人脸触发」,
 *   而价目条款里"单笔…以上…手续费"凑出了三个偶然词,分数只差 14%。
 *   1.10 仍然能挡住真正的"两条都像"("我上个月转账为什么失败"
 *   两条候选只差 2%,继续拒答 —— 那本来就该走记忆检索,不是制度)。
 */
export const MIN_GAP_RATIO = 1.1;

/** 固定拒答话术(不许模型改写:口径必须一致) */
export const POLICY_REFUSAL_TEXT =
  "关于这个问题,我没有在现行制度里找到能作为依据的条款。为避免给您错误信息,建议转人工核实。";

/**
 * 数字类问题的引导话术(不查制度,直接指向结构化能力)。
 *
 * ★ 措辞要覆盖两类:客户自己的数(余额/额度/持仓)与行情数(利率/汇率)。
 *   一开始只写"金额类问题我按你的账本算给你",客户问汇率时就会被这句话答懵 ——
 *   汇率既不是他的账本,也不该由制度回答。
 */
export const NUMERIC_REDIRECT_TEXT =
  "这类问题不在制度里 —— 金额、余额、额度要查您的账户,利率汇率要看行情;我按结构化数据给您核对,不靠检索拼数字。";

/**
 * "问的是我自己的钱"的词。
 *
 * ★ 注意这里**不能**简单写 `多少钱` 就拒答:
 *   「补卡多少钱」「单笔多少钱以上要人脸」问的是**制度里的价目与门槛**,
 *   正是制度问答该回答的。所以先看是否命中数字词,再用 RULE_CONTEXT 排除
 *   "规则语境",最后才判定为"查我自己的数据"。
 */
const NUMERIC_INTENT = /(余额|还剩多少|多少钱|额度|持仓|收益|利率|汇率|预算|欠款|可用)/;

/**
 * 规则语境:出现了这些词,说明问的是"制度里怎么规定",
 * 不是在问"我账户里现在有多少"。
 */
const RULE_CONTEXT =
  /(年费|手续费|工本费|管理费|收费|费用|费率|标准|以上|超过|上限|门槛|要人脸|预约|时限|多久|几天|几个工作日|有效期|份额|确认|撤销|补卡|补办|挂失)/;

/**
 * 是否为"数字类问题"(应绕开检索,交给结构化能力或直接拒答)。
 *
 * ★ 双重生效(32 文档 §4.4):
 *   ① 路由层优先把这类问题分给结构化能力(余额/额度/持仓);
 *   ② 能力内再兜一层 —— 即使被路由到制度问答,也绝不拿检索结果去凑数字。
 */
export function looksNumericQuestion(query: string): boolean {
  const text = String(query ?? "");
  if (!NUMERIC_INTENT.test(text)) return false;
  // 问的是"规则里的数"(年费多少/多少以上/多久到账)→ 属于制度问答
  if (RULE_CONTEXT.test(text)) return false;
  return true;
}

/**
 * "我自己那笔交易怎么了"——这类问题只能查台账/记忆,制度里没有答案。
 *
 * ★ 判据是"第一人称 + 过去事件 + 追问原因"。它看起来像制度问题
 *   (含"转账"这个词),但实际上问的是一笔**具体的、已经发生的**交易:
 *   「我上个月转账为什么失败」—— 制度只会说手续费怎么收,答不了这一笔。
 *   让它落进制度检索,系统就会拿"转账手续费"去回答"为什么失败" ——
 *   这正是最典型的"答非所问",而且客户会以为自己被敷衍。
 */
const PERSONAL_EVENT =
  /(我|我的|这笔|那笔|刚才|上个月|上个星期|上周|昨天|前天).{0,12}(为什么|为啥|怎么回|失败|没成功|没到账|扣了|少了|多了|不对劲)/;

export function looksPersonalEventQuestion(query: string): boolean {
  return PERSONAL_EVENT.test(String(query ?? ""));
}

/** 个人事件问题的引导话术(指向记忆检索/台账,而不是制度) */
export const PERSONAL_EVENT_TEXT =
  "这类问题要看您自己那笔交易的记录,制度里查不到。我可以在「最近操作」里帮您核对。";

export interface AcceptanceInput {
  bestScore: number;
  /** 第二名分数;只有一个候选时传 0 */
  secondScore: number;
  /** 查询词覆盖率 = 命中的查询词 / 全部查询词 */
  coverage: number;
}

export interface AcceptanceResult {
  accepted: boolean;
  /** 不接受时的原因(用于拒答理由与调试) */
  reason?: "no_hit" | "low_score" | "low_coverage" | "ambiguous";
  /** 面向客户的置信度(0~1,两位小数) */
  confidence: number;
}

/** 三条接受条件同时满足才作答,否则拒答 */
export function judgeAcceptance(input: AcceptanceInput): AcceptanceResult {
  const { bestScore, secondScore, coverage } = input;

  /**
   * 置信度只是"给客户看的把握程度",**不参与判定**。
   * 判定只看下面三条硬条件 —— 把分数揉进阈值会让口径变得不可解释。
   */
  const confidence =
    bestScore <= 0
      ? 0
      : Math.round(Math.min(0.99, coverage * 0.65 + Math.min(1, bestScore / 12) * 0.35) * 100) / 100;

  if (bestScore <= 0) return { accepted: false, reason: "no_hit", confidence: 0 };
  if (bestScore < MIN_SCORE) return { accepted: false, reason: "low_score", confidence };
  if (coverage < MIN_COVERAGE) return { accepted: false, reason: "low_coverage", confidence };
  // ★ 只有一条候选时没有"第二名",不构成歧义
  if (secondScore > 0 && bestScore < MIN_GAP_RATIO * secondScore) {
    return { accepted: false, reason: "ambiguous", confidence };
  }
  return { accepted: true, confidence };
}
