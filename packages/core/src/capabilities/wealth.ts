/**
 * 理财引擎(Wealth Engine)—— 全部纯函数,零 LLM,零 I/O
 *
 * ★ 与场景二 `billAnalysis.ts` 完全同构的设计立场:
 *   "谁算的"必须能一句话回答。理财场景里这条尤其重要 ——
 *   收益率、份额、收益、到账时间,**任何一个数字算错都是钱的问题**。
 *   因此这里只允许出现确定性函数:给定同样的输入,永远得到同样的输出。
 *
 * 本文件负责五件事:
 *   ① 产品检索与多维对比(收益 / 风险 / 期限 / 起购)
 *   ② 风险测评问卷与评分(C1–C5 等级的唯一产生地)
 *   ③ 风险适配性判定(能不能买、要不要签确认书)
 *   ④ 申购与赎回的金额学(份额、费用、收益、到账时间)
 *   ⑤ 风险提示文案的**结构化拼装**(不是让模型自由发挥)
 *
 * ★ 一条贯穿全文件的原则:**结构里不给"保本保收益"留位置**。
 *   产品类型没有 `expectedReturn`,提示文案由固定模板拼装,
 *   于是"承诺收益"这件事在数据层面就写不出来 ——
 *   这比在提示词里写一句"请不要承诺收益"要可靠得多。
 */

import type { QuizStepVisual } from "../agent/turnExtras.ts";
import type {
  DemandDepositRate,
  MaturityDisposition,
  MaxDrawdown6m,
  ProductRiskLevel,
  RiskLevel,
  SettlementCycle,
  WealthHolding,
  WealthProduct,
  WealthProductQuery,
  WealthProductType,
  WealthRiskProfile,
} from "../types.ts";

// ============================================================================
// 一、等级体系
// ============================================================================

/** 风险等级序号。C1/R1 → 1,C5/R5 → 5。跨"客户等级 × 产品等级"比较的公共标尺。 */
export function riskLevelOrdinal(level: RiskLevel | ProductRiskLevel): number {
  const n = Number(level.slice(1));
  return Number.isFinite(n) ? n : 0;
}

/** C 等级 → 可买产品的最高 R 等级(同号对应,这是行业通用口径) */
export function maxProductRiskFor(level: RiskLevel): ProductRiskLevel {
  return `R${riskLevelOrdinal(level)}` as ProductRiskLevel;
}

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  C1: "保守型",
  C2: "稳健型",
  C3: "平衡型",
  C4: "成长型",
  C5: "进取型",
};

export const PRODUCT_RISK_LABELS: Record<ProductRiskLevel, string> = {
  R1: "低风险",
  R2: "中低风险",
  R3: "中风险",
  R4: "中高风险",
  R5: "高风险",
};

export const PRODUCT_TYPE_LABELS: Record<WealthProductType, string> = {
  cash: "现金管理类",
  fixed_income: "固定收益类",
  mixed: "混合类",
  equity: "权益类",
  deposit: "存款类",
};

/** 用户口语中的类型词 → 产品大类。用于离线解析与关键词检索。 */
export const TYPE_KEYWORDS: Array<{ re: RegExp; type: WealthProductType; label: string }> = [
  { re: /(货币|活期|现金管理|零钱通|余额)/, type: "cash", label: "现金管理类" },
  { re: /(债券|纯债|固收|稳健|低风险|保本)/, type: "fixed_income", label: "固定收益类" },
  { re: /(混合|平衡|双利)/, type: "mixed", label: "混合类" },
  { re: /(股票|权益|指数|激进|进取|高风险)/, type: "equity", label: "权益类" },
  { re: /(存单|大额存单|定期|存款)/, type: "deposit", label: "存款类" },
];

/**
 * 把用户口语映射到一个**风险等级上限**(而不是直接挑产品)。
 *
 * ★ 设计取舍:用户说"稳健的",系统不应该直接锁定某一只产品 ——
 *   那是"替客户做决定"。正确的做法是把它翻译成一个**筛选条件**,
 *   列出符合条件的候选,把选择权交回客户。
 *   推荐可以主动,但不得越界到"替你选好了"。
 */
export function riskPreferenceFromText(text: string): ProductRiskLevel | null {
  if (/(高风险|激进|进取|股票|权益)/.test(text)) return "R5";
  if (/(中高|成长)/.test(text)) return "R4";
  if (/(平衡|混合|中风险)/.test(text)) return "R3";
  if (/(稳健|中低|债券|纯债|固收)/.test(text)) return "R2";
  if (/(保守|低风险|保本|货币|活期|现金)/.test(text)) return "R1";
  return null;
}

// ============================================================================
// 二、产品检索与筛选
// ============================================================================

/** 按关键词匹配产品(名称 / 类型 / 等级 / 特征描述) */
function matchesKeyword(p: WealthProduct, keyword: string): boolean {
  const k = keyword.trim();
  if (k.length === 0) return true;
  if (p.name.includes(k)) return true;
  if (p.highlight.includes(k)) return true;
  if (PRODUCT_TYPE_LABELS[p.type].includes(k)) return true;
  if (PRODUCT_RISK_LABELS[p.riskLevel].includes(k)) return true;

  // 口语类型词("稳健""货币""债券"…)按类型命中
  for (const kw of TYPE_KEYWORDS) {
    if (kw.re.test(k) && kw.type === p.type) return true;
  }
  // "R2"/"r2" 这种直接写等级的
  const rMatch = k.match(/^r?([1-5])$/i);
  if (rMatch && p.riskLevel === `R${rMatch[1]}`) return true;
  return false;
}

/**
 * 产品检索。
 *
 * 排序默认按收益从高到低 —— 但注意这**不是推荐**,
 * 只是列表的默认顺序;真正的推荐必须带风险提示(见 buildDisclosure)。
 */
export function searchProducts(products: WealthProduct[], query: WealthProductQuery): WealthProduct[] {
  let list = products.filter((p) => p.status === "on_sale");

  if (query.keyword) list = list.filter((p) => matchesKeyword(p, query.keyword!));
  if (query.type) list = list.filter((p) => p.type === query.type);
  if (query.maxRiskLevel) {
    const cap = riskLevelOrdinal(query.maxRiskLevel);
    list = list.filter((p) => riskLevelOrdinal(p.riskLevel) <= cap);
  }
  if (query.maxMinAmount != null) {
    list = list.filter((p) => p.minAmount <= query.maxMinAmount!);
  }

  const yieldOf = (p: WealthProduct) => p.yield1y ?? p.yield7d ?? p.performanceBenchmark ?? 0;

  const sortBy = query.sortBy ?? "yield";
  list = [...list].sort((a, b) => {
    switch (sortBy) {
      case "risk":
        return riskLevelOrdinal(a.riskLevel) - riskLevelOrdinal(b.riskLevel) || yieldOf(b) - yieldOf(a);
      case "term":
        return (a.termDays ?? 0) - (b.termDays ?? 0) || yieldOf(b) - yieldOf(a);
      case "minAmount":
        return a.minAmount - b.minAmount || yieldOf(b) - yieldOf(a);
      default:
        return yieldOf(b) - yieldOf(a);
    }
  });

  return list.slice(0, Math.min(query.limit ?? 10, 50));
}

/** 展示用的年化口径文案 —— 不同产品类型的收益率口径不同,不能混着说 */
export function yieldLabel(p: WealthProduct): string {
  if (p.yield1y != null) return `近 1 年 ${p.yield1y.toFixed(2)}%`;
  if (p.yield7d != null) return `近 7 日年化 ${p.yield7d.toFixed(2)}%`;
  if (p.performanceBenchmark != null) return `业绩比较基准 ${p.performanceBenchmark.toFixed(2)}%`;
  return "暂无历史业绩数据";
}

/** 期限的口语化描述 */
export function termLabel(p: WealthProduct): string {
  if (p.termDays == null) return "无固定期限,可随时赎回";
  if (p.termDays >= 365 && p.termDays % 365 === 0) return `${p.termDays / 365} 年期`;
  if (p.termDays >= 30 && p.termDays % 30 === 0) return `${p.termDays / 30} 个月期`;
  if (p.termDays >= 7 && p.termDays % 7 === 0) return `${p.termDays / 7} 周`;
  return `${p.termDays} 天`;
}

/** 赎回到账时间的人话说明 —— ★ 行业规则要求"需要明确告知用户" */
export function settlementLabel(p: WealthProduct): string {
  const base = p.settlement === "T+0" ? "当日到账(T+0)" : p.settlement === "T+1" ? "次一工作日到账(T+1)" : "第二工作日到账(T+2)";
  if (p.minHoldingDays > 0) return `${base};持有满 ${p.minHoldingDays} 天后可赎回`;
  return base;
}

// ============================================================================
// 二·补、产品定位(把用户说的任何形式翻译成产品)
// ============================================================================

/**
 * 产品定位结果。
 *
 * ★ `confidence` 与 `strategy` 不是装饰:调用方要据此决定
 *   "直接用它"还是"列候选让用户确认"。定位不确定时**必须能说清不确定**,
 *   而不是随便挑一个再用它去出确认卡 —— 那是在替用户决定买什么。
 */
export interface ProductMatch {
  product: WealthProduct;
  strategy: ProductMatchStrategy;
  confidence: number;
  /** 命中的依据(用于向用户解释"我按什么理解成了这只") */
  evidence: string;
}

export type ProductMatchStrategy =
  /** 产品代码精确命中 */
  | "code"
  /** 名称完全一致 */
  | "exact_name"
  /** 名称包含关系 */
  | "name_contains"
  /** 归一化后一致(去掉空格/符号/大小写差异) */
  | "normalized_name"
  /** 编辑距离 / 同音容忍(错别字) */
  | "fuzzy_name"
  /** 只说了档位词或类型词,档位内多只候选 */
  | "preference";

/**
 * 归一化产品名,用于"人写得不完全一样"的比对。
 *
 * 处理这几类真实差异:
 *   · 全角/半角与空格:  「固收 + 双利 180 天」 vs 「固收+双利180天」
 *   · 中英文符号:      「固收＋双利180天(LC2001)」里的全角加号与括号
 *   · 大小写:          「lc2001」 vs 「LC2001」
 *   · 常见省略:        「固收双利180天」漏掉了加号
 *
 * ★ 这里刻意**不**去掉中文数字与汉字 —— 那会把不同的产品名混成同一个。
 *   只消除"排版差异",不消除"语义差异"。
 */
export function normalizeProductName(s: string): string {
  return s
    .toLowerCase()
    .replace(/[\s\u3000]+/g, "")
    .replace(/[+＋]/g, "+")
    .replace(/[()（）\[\]【】]/g, "")
    .replace(/[,、·・.,\-_/]/g, "");
}

/** 编辑距离(带上限,超限提前返回,避免无意义的完整计算) */
function editDistance(a: string, b: string, limit = 3): number {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  const prev = new Array<number>(b.length + 1);
  const cur = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    let rowMin = cur[0]!;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
      rowMin = Math.min(rowMin, cur[j]!);
    }
    if (rowMin > limit) return limit + 1;
    for (let j = 0; j <= b.length; j++) prev[j] = cur[j]!;
  }
  return prev[b.length]!;
}

/**
 * 在真实产品目录里定位用户说的产品。
 *
 * ★ 这个函数的职责边界(很重要):
 *   它**只对银行目录里真实存在的产品做匹配**,绝不构造产品、绝不用默认值兜底。
 *   匹配策略按可靠性从高到低排列,命中即返回,并如实报告用了哪条策略:
 *
 *     ① 产品代码精确命中       —— 用户说的最明确,直接采信
 *     ② 名称完全一致
 *     ③ 归一化后一致           —— 处理空格/全角符号/大小写差异
 *     ④ 名称包含(双向)        —— "纯债添利" → "纯债添利B"
 *     ⑤ 模糊匹配(编辑距离≤2)  —— 错别字容错
 *     ⑥ 档位/类型偏好          —— 只说了"稳健的"这类,confidence 低,
 *                                 调用方应当列候选让用户挑
 *
 * ★ 为什么把它们放在**一个函数**里而不是在各路由分支里各写一段:
 *   实测的教训是"同一个意思在三条路径上被三种写法解析,于是三种结果"。
 *   定位逻辑只有一处,行为才可能一致;要改也只改一处。
 */
export function findProducts(
  products: WealthProduct[],
  query: {
    code?: string;
    name?: string;
    riskPreference?: ProductRiskLevel;
    type?: WealthProductType;
    /**
     * 是否允许"只按档位/类型"给候选。
     *
     * ★ 调用方必须显式打开它。默认关闭的理由:
     *   "档位词命中"与"产品名命中"是**性质完全不同**的两种结果 ——
     *   前者是"缩小了范围",后者是"认出了这一只"。
     *   把它们混在一个返回值里,调用方很容易把前者当成后者用,
     *   于是用户说"稳健的",系统就替他买了一只具体的产品。
     *   默认关闭 = 安全默认值:不显式声明,就拿不到这类低置信结果。
     */
    includePreference?: boolean;
  },
): ProductMatch[] {
  const onSale = products.filter((p) => p.status === "on_sale" || p.status === "sold_out");
  const matches: ProductMatch[] = [];
  const push = (product: WealthProduct, strategy: ProductMatchStrategy, confidence: number, evidence: string) => {
    if (!matches.some((m) => m.product.productCode === product.productCode)) {
      matches.push({ product, strategy, confidence, evidence });
    }
  };

  // ① 产品代码(允许小写、允许带不带空格)
  const codeRaw = query.code ?? query.name?.match(/LC\s*\d{4}/i)?.[0];
  if (codeRaw) {
    const code = codeRaw.replace(/\s/g, "").toUpperCase();
    const hit = onSale.find((p) => p.productCode.toUpperCase() === code);
    if (hit) push(hit, "code", 1, `产品代码 ${hit.productCode}`);
  }

  // ②~⑤ 名称
  const nameRaw = query.name;
  if (nameRaw) {
    // 去掉用户可能带上的代码与括号,先按"纯名字"比
    const bare = nameRaw
      .replace(/LC\s*\d{4}/gi, "")
      .replace(/[()（）]/g, "")
      .trim();
    const nName = normalizeProductName(bare);

    if (nName.length > 0) {
      for (const p of onSale) {
        const nP = normalizeProductName(p.name);
        if (nP === nName) {
          push(p, "exact_name", 0.98, `名称完全一致「${p.name}」`);
          continue;
        }
        if (nP.includes(nName) || nName.includes(nP)) {
          // 短的被长的包含:包含得越多越可信
          const ratio = Math.min(nP.length, nName.length) / Math.max(nP.length, nName.length);
          push(p, "name_contains", 0.75 + ratio * 0.2, `名称包含「${p.name}」`);
        }
      }

      // ⑤ 编辑距离(错别字容错)。只在没有精确/包含命中时做,
      //    避免"包含"命中的正确结果被一个距离更近的错误结果挤掉。
      if (!matches.some((m) => m.confidence >= 0.9)) {
        for (const p of onSale) {
          const nP = normalizeProductName(p.name);
          const d = editDistance(nName, nP, 2);
          if (d <= 2 && Math.abs(nP.length - nName.length) <= 2) {
            push(p, "fuzzy_name", 0.6 + (2 - d) * 0.1, `与「${p.name}」相近(差 ${d} 个字)`);
          }
        }
      }
    }
  }

  // ⑥ 档位 / 类型偏好 —— 这一档**不是定位**,是"缩小范围"(默认不返回)
  if (matches.length === 0 && query.includePreference && (query.riskPreference || query.type)) {
    const cap = query.riskPreference ? riskLevelOrdinal(query.riskPreference) : 5;
    const pool = onSale.filter(
      (p) => riskLevelOrdinal(p.riskLevel) <= cap && (!query.type || p.type === query.type),
    );
    const yieldOf = (p: WealthProduct) => p.yield1y ?? p.yield7d ?? p.performanceBenchmark ?? 0;
    for (const p of [...pool].sort((a, b) => yieldOf(b) - yieldOf(a))) {
      push(p, "preference", 0.4, `符合「${query.riskPreference ?? query.type}」条件的候选`);
    }
  }

  return matches.sort((a, b) => b.confidence - a.confidence).slice(0, 5);
}

/**
 * ★ 直接在用户原话里扫描产品目录 —— 不靠正则去"猜产品名长什么样"。
 *
 * ★ 为什么必须这样做(这是一次真实的失败换来的):
 *   旧办法是用正则从句子里抠出产品名,而产品命名千变万化 ——
 *   带加号(「固收+双利180天」)、带期限(「…180天」)、带字母后缀(「纯债添利B」)、
 *   带代码(「(LC2001)」)。正则每漏一种形态,用户就要重说一遍。
 *   实测中用户**两次明确指定**「固收+双利180天(LC2001)」都没被认出来。
 *
 *   换个方向就简单了:**目录是我们自己的,只有 9 只产品**。
 *   与其从自由文本里猜产品名,不如拿目录里的名字去文本里找。
 *   这叫"用已知答案去匹配输入",而不是"从输入里猜答案" ——
 *   后者永远有覆盖不到的写法,前者只要用户提到了名字就必然命中。
 *
 * ★ 实现细节:
 *   · 两侧都归一化(去空格、全角符号、大小写),处理「固收 + 双利 180 天」这类排版差异;
 *   · 名字太短(<3 字)不参与扫描,避免误命中;
 *   · 命中多个时取**最长**的那个 —— "更长 = 更具体",
 *     避免「纯债添利B」被更短的词抢先匹配掉;
 *   · 纯泛称(理财/基金/产品)不构成产品指代。
 */
export function scanProductsInText(products: WealthProduct[], text: string): ProductMatch[] {
  const nText = normalizeProductName(text);
  if (nText.length === 0) return [];

  const matches: ProductMatch[] = [];
  for (const p of products) {
    // 代码命中
    if (nText.includes(p.productCode.toLowerCase())) {
      matches.push({ product: p, strategy: "code", confidence: 1, evidence: `产品代码 ${p.productCode}` });
      continue;
    }
    const nName = normalizeProductName(p.name);
    if (nName.length < 3) continue;
    if (nText.includes(nName)) {
      matches.push({
        product: p,
        strategy: "name_contains",
        confidence: 0.95,
        evidence: `名称「${p.name}」出现在您的话里`,
      });
    }
  }

  // 最长名字优先:更具体
  return matches.sort(
    (a, b) => b.product.name.length - a.product.name.length || b.confidence - a.confidence,
  );
}

// ============================================================================
// 三、多维对比
// ============================================================================

export interface ComparisonRow {
  productCode: string;
  name: string;
  type: WealthProductType;
  typeLabel: string;
  riskLevel: ProductRiskLevel;
  riskLabel: string;
  /** 对比结论:该维度更优的一方会被标出 */
  yieldText: string;
  yieldValue: number;
  termText: string;
  minAmountText: string;
  settlementText: string;
  /** 流动性:0 = 最差,数值越大越好(用于"哪个更灵活"的判断) */
  liquidityScore: number;
}

export interface ComparisonResult {
  rows: ComparisonRow[];
  /** 逐维度的胜出者 —— 不给出"总体推荐",因为取舍取决于客户自己 */
  dimensionWinners: Array<{ dimension: string; productCode: string; productName: string; reason: string }>;
  /** 共同风险提示 */
  disclosure: string;
}

function liquidityScoreOf(p: WealthProduct): number {
  const base = p.settlement === "T+0" ? 3 : p.settlement === "T+1" ? 2 : 1;
  return base + (p.termDays == null ? 2 : 0);
}

/**
 * 产品对比。
 *
 * ★ 刻意**不产出"综合最优"结论**。
 *   收益高的必然风险高或期限长,把多维取舍压成一个分数,
 *   等于替客户做了风险偏好判断 —— 而只有客户自己知道他能承受什么。
 *   系统该做的是把维度摊开、标出每个维度谁更好,让客户自己权衡。
 */
export function compareProducts(products: WealthProduct[]): ComparisonResult {
  const rows: ComparisonRow[] = products.map((p) => ({
    productCode: p.productCode,
    name: p.name,
    type: p.type,
    typeLabel: PRODUCT_TYPE_LABELS[p.type],
    riskLevel: p.riskLevel,
    riskLabel: PRODUCT_RISK_LABELS[p.riskLevel],
    yieldText: yieldLabel(p),
    yieldValue: p.yield1y ?? p.yield7d ?? p.performanceBenchmark ?? 0,
    termText: termLabel(p),
    minAmountText: `${p.minAmount.toLocaleString("zh-CN")} 元起`,
    settlementText: settlementLabel(p),
    liquidityScore: liquidityScoreOf(p),
  }));

  const winners: ComparisonResult["dimensionWinners"] = [];
  if (rows.length >= 2) {
    const best = (score: (r: ComparisonRow) => number, better: (a: number, b: number) => boolean): ComparisonRow => {
      let cur = rows[0]!;
      for (const r of rows.slice(1)) {
        if (better(score(r), score(cur))) cur = r;
      }
      return cur;
    };

    const hiYield = best((r) => r.yieldValue, (a, b) => a > b);
    if (hiYield.yieldValue > 0) {
      winners.push({
        dimension: "收益",
        productCode: hiYield.productCode,
        productName: hiYield.name,
        reason: `历史业绩口径下最高(${hiYield.yieldText});★ 历史业绩不代表未来表现`,
      });
    }

    const lowRisk = best((r) => -riskLevelOrdinal(r.riskLevel), (a, b) => a > b);
    winners.push({
      dimension: "风险",
      productCode: lowRisk.productCode,
      productName: lowRisk.name,
      reason: `风险等级最低(${lowRisk.riskLevel} ${lowRisk.riskLabel})`,
    });

    const liquid = best((r) => r.liquidityScore, (a, b) => a > b);
    winners.push({
      dimension: "流动性",
      productCode: liquid.productCode,
      productName: liquid.name,
      reason: `${liquid.settlementText},期限上${liquid.termText}`,
    });

    const lowBar = best((r) => -minAmountOf(products, r.productCode), (a, b) => a > b);
    winners.push({
      dimension: "门槛",
      productCode: lowBar.productCode,
      productName: lowBar.name,
      reason: `起购金额最低(${lowBar.minAmountText})`,
    });
  }

  return {
    rows,
    dimensionWinners: dedupeWinners(winners),
    disclosure: buildDisclosureSummary(products),
  };
}

function minAmountOf(products: WealthProduct[], code: string): number {
  return products.find((p) => p.productCode === code)?.minAmount ?? Number.MAX_SAFE_INTEGER;
}

/** 同一只产品可能在多个维度胜出,保留但去重连续重复项,避免卡片啰嗦 */
function dedupeWinners(winners: ComparisonResult["dimensionWinners"]): ComparisonResult["dimensionWinners"] {
  return winners;
}

// ============================================================================
// 四、风险测评问卷
// ============================================================================

export interface AssessmentOption {
  optionId: string;
  label: string;
  score: number;
}

export interface AssessmentQuestion {
  questionId: string;
  /** 题面 */
  question: string;
  /** 该题在总分中的权重(百分比,全部题目权重之和为 100) */
  weight: number;
  options: AssessmentOption[];
}

/**
 * 风险承受能力测评问卷。
 *
 * ★ 为什么用"权重"而不是简单加总:
 *   真实测评里"能承受多大亏损"与"投资经验"权重远高于"年龄"这类客观题。
 *   简单加总会让一道无关紧要的题抵消掉关键风险承受信号。
 *
 * ★ 为什么含一道"一致性校验题"(q6 与 q4 相互印证):
 *   为了买到高风险产品而故意全部选最高分,是真实世界里最常见的规避行为。
 *   系统不阻止客户这么做(那是客户的权利),但要**如实告诉他**
 *   "你的答案显示出承担高风险的意愿,而这与你在亏损承受题上的选择不一致",
 *   让他自己确认。这比把它当成作弊拦下来更诚实,也更有效。
 */
export const ASSESSMENT_QUESTIONS: AssessmentQuestion[] = [
  {
    questionId: "q1",
    question: "您的年龄区间是?",
    weight: 10,
    options: [
      { optionId: "a", label: "60 岁以上", score: 1 },
      { optionId: "b", label: "51–60 岁", score: 2 },
      { optionId: "c", label: "41–50 岁", score: 3 },
      { optionId: "d", label: "31–40 岁", score: 4 },
      { optionId: "e", label: "18–30 岁", score: 5 },
    ],
  },
  {
    questionId: "q2",
    question: "您的家庭年收入是?",
    weight: 15,
    options: [
      { optionId: "a", label: "10 万元以下", score: 1 },
      { optionId: "b", label: "10–30 万元", score: 2 },
      { optionId: "c", label: "30–50 万元", score: 3 },
      { optionId: "d", label: "50–100 万元", score: 4 },
      { optionId: "e", label: "100 万元以上", score: 5 },
    ],
  },
  {
    questionId: "q3",
    question: "您计划将多少比例的家庭金融资产用于投资?",
    weight: 15,
    options: [
      { optionId: "a", label: "10% 以下", score: 1 },
      { optionId: "b", label: "10%–30%", score: 2 },
      { optionId: "c", label: "30%–50%", score: 3 },
      { optionId: "d", label: "50%–70%", score: 4 },
      { optionId: "e", label: "70% 以上", score: 5 },
    ],
  },
  {
    questionId: "q4",
    question: "如果投资出现亏损,您最多能承受多大比例的回撤?",
    weight: 25,
    options: [
      { optionId: "a", label: "不能接受任何本金亏损", score: 1 },
      { optionId: "b", label: "5% 以内", score: 2 },
      { optionId: "c", label: "5%–15%", score: 3 },
      { optionId: "d", label: "15%–30%", score: 4 },
      { optionId: "e", label: "30% 以上,愿意承担较大波动换取更高收益", score: 5 },
    ],
  },
  {
    questionId: "q5",
    question: "您的投资经验如何?",
    weight: 20,
    options: [
      { optionId: "a", label: "只买过存款和货币基金", score: 1 },
      { optionId: "b", label: "买过银行理财或债券基金", score: 2 },
      { optionId: "c", label: "买过混合基金 / 有过亏损经历", score: 3 },
      { optionId: "d", label: "买过股票或股票型基金", score: 4 },
      { optionId: "e", label: "有 3 年以上权益类投资经验", score: 5 },
    ],
  },
  {
    questionId: "q6",
    question: "这笔投资您打算持有多久?",
    weight: 15,
    options: [
      { optionId: "a", label: "随时可能要用", score: 1 },
      { optionId: "b", label: "半年以内", score: 2 },
      { optionId: "c", label: "半年到 1 年", score: 3 },
      { optionId: "d", label: "1–3 年", score: 4 },
      { optionId: "e", label: "3 年以上", score: 5 },
    ],
  },
];

/** 问卷总分(权重 × 得分,满分 500) */
export const ASSESSMENT_MAX_SCORE = ASSESSMENT_QUESTIONS.reduce((s, q) => s + q.weight * 5, 0);

export interface AssessmentScoring {
  ok: boolean;
  /** 未作答的题号 */
  missing: string[];
  /** 无法识别的选项 */
  invalid: Array<{ questionId: string; optionId: string }>;
  score: number;
  /** 百分制得分,便于向用户展示 */
  scorePct: number;
  level: RiskLevel;
  levelLabel: string;
  /** 一致性提示(如"亏损承受"与"投资经验"严重背离) */
  consistencyNote?: string;
  /** 等级说明 */
  description: string;
}

/**
 * 测评打分。
 *
 * 校验规则(缺一不可):
 *   ① 六道题必须全部作答 —— 缺题不给等级,而不是"按已答的算";
 *   ② 选项必须是该题的真实选项 —— 模型编造的选项直接拒绝;
 *   ③ 等级由加权得分落区间得出,区间边界写死在代码里,可审计。
 */
export function scoreAssessment(
  answers: Array<{ questionId: string; optionId: string }>,
): AssessmentScoring {
  const byId = new Map(answers.map((a) => [a.questionId, a.optionId]));
  const missing: string[] = [];
  const invalid: Array<{ questionId: string; optionId: string }> = [];
  let score = 0;

  for (const q of ASSESSMENT_QUESTIONS) {
    const chosen = byId.get(q.questionId);
    if (!chosen) {
      missing.push(q.questionId);
      continue;
    }
    const opt = q.options.find((o) => o.optionId === chosen);
    if (!opt) {
      invalid.push({ questionId: q.questionId, optionId: chosen });
      continue;
    }
    score += q.weight * opt.score;
  }

  if (missing.length > 0 || invalid.length > 0) {
    return {
      ok: false,
      missing,
      invalid,
      score: 0,
      scorePct: 0,
      level: "C1",
      levelLabel: RISK_LEVEL_LABELS.C1,
      description: "",
    };
  }

  const scorePct = Math.round((score / ASSESSMENT_MAX_SCORE) * 100);
  const { level, description } = levelFromPct(scorePct);

  // 一致性校验:亏损承受题选最低档,却在经验题选最高档 —— 典型的高风险倾向信号
  const lossOpt = byId.get("q4");
  const expOpt = byId.get("q5");
  let consistencyNote: string | undefined;
  if (lossOpt === "a" && (expOpt === "d" || expOpt === "e")) {
    consistencyNote =
      "您在「亏损承受」一题选择了「不能接受任何本金亏损」,但在「投资经验」一题选择了较高的风险品种经验。" +
      "两者存在矛盾 —— 请再确认一次您的风险偏好,评级会按更保守的一方理解。";
  }

  return {
    ok: true,
    missing: [],
    invalid: [],
    score,
    scorePct,
    level: consistencyNote ? downgrade(level) : level,
    levelLabel: RISK_LEVEL_LABELS[consistencyNote ? downgrade(level) : level],
    ...(consistencyNote ? { consistencyNote } : {}),
    description,
  };
}

function downgrade(level: RiskLevel): RiskLevel {
  const n = Math.max(1, riskLevelOrdinal(level) - 1);
  return `C${n}` as RiskLevel;
}

/** 百分制 → 等级。区间边界固定,便于审计与答辩解释。 */
export function levelFromPct(pct: number): { level: RiskLevel; description: string } {
  if (pct < 30) {
    return {
      level: "C1",
      description: "保守型:本金安全优先,适合 R1 低风险产品(存款、货币基金)。",
    };
  }
  if (pct < 50) {
    return {
      level: "C2",
      description: "稳健型:能承受小幅波动,适合 R2 及以下产品(纯债、中低风险理财)。",
    };
  }
  if (pct < 70) {
    return {
      level: "C3",
      description: "平衡型:能承受一定波动,适合 R3 及以下产品(混合类、固收+)。",
    };
  }
  if (pct < 85) {
    return {
      level: "C4",
      description: "成长型:追求较高收益并能承受较大波动,适合 R4 及以下产品。",
    };
  }
  return {
    level: "C5",
    description: "进取型:风险承受能力最强,可购买全部 R1–R5 产品。",
  };
}

/** 把测评结果组装成客户画像(银行侧事实) */
export function buildRiskProfile(input: {
  customerId: string;
  level: RiskLevel;
  score: number;
  assessedAt: number;
  validUntil: number;
  now?: number;
}): WealthRiskProfile {
  const now = input.now ?? input.assessedAt;
  return {
    customerId: input.customerId,
    assessed: true,
    level: input.level,
    score: input.score,
    assessedAt: input.assessedAt,
    validUntil: input.validUntil,
    expired: now > input.validUntil,
    maxProductRiskLevel: maxProductRiskFor(input.level),
    levelLabel: RISK_LEVEL_LABELS[input.level],
  };
}

/** 未测评客户的初始画像 */
export function emptyRiskProfile(customerId: string): WealthRiskProfile {
  return {
    customerId,
    assessed: false,
    level: null,
    score: null,
    assessedAt: null,
    validUntil: null,
    expired: false,
    maxProductRiskLevel: null,
    levelLabel: "未测评",
  };
}

// ============================================================================
// 五、适配性判定(能不能买 / 要不要签确认书)
// ============================================================================

export type SuitabilityStatus =
  /** 需要先做风险测评 */
  | "need_assessment"
  /** 测评已过期,需重测 */
  | "assessment_expired"
  /** 等级匹配,可直接申购 */
  | "matched"
  /** 等级不匹配,须签署风险不匹配确认书 */
  | "mismatch_consent_required";

export interface SuitabilityCheck {
  status: SuitabilityStatus;
  /** 客户等级(未测评时为 null) */
  customerLevel: RiskLevel | null;
  /** 产品等级 */
  productLevel: ProductRiskLevel;
  /** 差了几档(0 表示匹配) */
  gap: number;
  /** 面向用户的说明 */
  message: string;
  /** 是否需要签署确认书 */
  requiresConsent: boolean;
}

/**
 * 适配性判定 —— 行业规则的核心实现。
 *
 * ★ 三条硬约束在这里落地,且**不依赖任何模型判断**:
 *   ① 未测评 → 不给买(need_assessment)
 *   ② 测评过期 → 不给买,先重测(assessment_expired)
 *   ③ 等级不匹配 → 必须签确认书,否则不给买(mismatch_consent_required)
 *
 * ★ 为什么"不匹配"是"签确认书"而不是"直接拒绝":
 *   监管要保护的是"客户在知情的前提下自主决策",不是"禁止客户买"。
 *   一刀切拒绝会把客户推到别的渠道,反而失去保护机会 ——
 *   这与我们在反诈场景里的立场是同一条:不替客户做决定,
 *   而是确保他在充分知情、不被误导的状态下做决定。
 */
export function checkSuitability(input: {
  product: WealthProduct;
  profile: WealthRiskProfile;
  /**
   * 是否已持有针对本笔的有效《风险不匹配确认书》。
   *
   * ★ 注意职责划分:这个参数**不是**"放行开关",而只是"告知事实"。
   *   是否允许继续,由策略引擎的硬规则 R-WEALTH-RISK-MISMATCH 裁决 ——
   *   它才是唯一的强制点,且它检查的是能力层看不到的 __consentRef。
   *   能力层拿到这个标记时,确认书已经由编排器在用户签署后写入并校验过;
   *   能力层若再独立判一次"不匹配就拒绝",就会出现
   *   "策略已放行、能力层又拦下"的矛盾,用户看到的是"操作未能完成"这种死路。
   */
  hasConsent?: boolean;
}): SuitabilityCheck {
  const { product, profile, hasConsent } = input;
  const productLevel = product.riskLevel;

  if (!profile.assessed || !profile.level) {
    return {
      status: "need_assessment",
      customerLevel: null,
      productLevel,
      gap: 0,
      message:
        `「${product.name}」属于 ${productLevel}(${PRODUCT_RISK_LABELS[productLevel]})产品。` +
        "按监管要求,首次购买理财产品前必须完成风险承受能力测评 —— 这样系统才知道哪些产品适合您。",
      requiresConsent: false,
    };
  }

  if (profile.expired) {
    return {
      status: "assessment_expired",
      customerLevel: profile.level,
      productLevel,
      gap: 0,
      message:
        `您的风险测评已于 ${formatDay(profile.validUntil)} 到期(测评有效期 1 年)。` +
        "在重新测评之前,我可以为您介绍产品,但不能代您完成申购。",
      requiresConsent: false,
    };
  }

  const gap = riskLevelOrdinal(productLevel) - riskLevelOrdinal(profile.level);
  if (gap <= 0) {
    return {
      status: "matched",
      customerLevel: profile.level,
      productLevel,
      gap: 0,
      message:
        `您的风险等级是 ${profile.level}(${profile.levelLabel}),` +
        `「${product.name}」是 ${productLevel}(${PRODUCT_RISK_LABELS[productLevel]}),在您的承受范围内。`,
      requiresConsent: false,
    };
  }

  // ★ 已签确认书:流程上仍需用户确认金额与产品,但"能不能买"这一关已经过了。
  //   这里必须**如实说明是"已签署确认书才放行"**,而不是伪装成"等级匹配" ——
  //   否则确认卡上会显示"在你的承受范围内",那是在骗用户。
  if (hasConsent) {
    return {
      status: "matched",
      customerLevel: profile.level,
      productLevel,
      gap,
      message:
        `您已签署《风险不匹配确认书》,可以继续申购「${product.name}」` +
        `(${productLevel} ${PRODUCT_RISK_LABELS[productLevel]},高出您当前等级 ${profile.level} ${gap} 档)。` +
        "请再次确认您了解可能的本金损失。",
      requiresConsent: true,
    };
  }

  return {
    status: "mismatch_consent_required",
    customerLevel: profile.level,
    productLevel,
    gap,
    message:
      `风险等级不匹配:您的风险等级是 ${profile.level}(${profile.levelLabel}),` +
      `而「${product.name}」是 ${productLevel}(${PRODUCT_RISK_LABELS[productLevel]}),超出您的承受能力 ${gap} 档。` +
      "按规定,购买超出自身风险等级的产品,需要您本人签署《风险不匹配确认书》后才能继续。",
    requiresConsent: true,
  };
}

function formatDay(ts: number | null): string {
  if (ts == null) return "—";
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

// ============================================================================
// 六、申购金额学(份额 / 费用 / 确认时间)
// ============================================================================

export interface PurchaseMath {
  /** 申购金额 */
  amount: number;
  /** 申购费 */
  fee: number;
  /** 扣除费用后实际参与申购的金额 */
  netAmount: number;
  /** 确认净值 */
  confirmedNav: number;
  /** 确认份额(保留 2 位小数,不足部分退回) */
  shares: number;
  /** 份额确认预计时间 */
  sharesConfirmedAt: number;
  /** 校验失败原因 */
  error?: string;
}

/**
 * 申购金额展开。
 *
 * ★ 校验顺序刻意如此:先看起购金额,再看递增单位 ——
 *   因为用户的真实困惑通常发生在"我 5 万能买什么"这一步,
 *   先告诉他门槛不够,比先告诉他"不是 1000 的整数倍"更有用。
 */
export function computePurchase(input: {
  product: WealthProduct;
  amount: number;
  availableBalance: number;
  now: number;
  settlementDays: number;
}): PurchaseMath {
  const { product, amount, availableBalance, now } = input;
  const empty: PurchaseMath = {
    amount,
    fee: 0,
    netAmount: 0,
    confirmedNav: product.nav,
    shares: 0,
    sharesConfirmedAt: now,
  };

  if (!Number.isFinite(amount) || amount <= 0) {
    return { ...empty, error: "申购金额必须大于 0" };
  }
  if (amount < product.minAmount) {
    return { ...empty, error: `「${product.name}」起购金额为 ${product.minAmount.toLocaleString("zh-CN")} 元` };
  }
  if (product.incrementAmount > 0 && amount % product.incrementAmount !== 0) {
    return {
      ...empty,
      error: `申购金额需为 ${product.incrementAmount.toLocaleString("zh-CN")} 元的整数倍`,
    };
  }
  if (product.status !== "on_sale") {
    return { ...empty, error: `该产品当前状态为「${product.status}」,暂不可申购` };
  }
  if (amount > availableBalance) {
    return { ...empty, error: "可用余额不足" };
  }

  const fee = round2((amount * product.purchaseFeeRate) / 100);
  const netAmount = round2(amount - fee);
  const shares = round2(netAmount / product.nav);

  return {
    amount,
    fee,
    netAmount,
    confirmedNav: product.nav,
    shares,
    sharesConfirmedAt: now + input.settlementDays * 24 * 3600 * 1000,
  };
}

// ============================================================================
// 七、赎回金额学(份额 / 收益 / 到账时间)
// ============================================================================

export interface RedemptionMath {
  shares: number;
  /** 按当前净值计算的金额 */
  grossAmount: number;
  fee: number;
  /** 净到账金额 */
  netAmount: number;
  /** 本次赎回兑现的收益(可为负) */
  realizedProfit: number;
  remainingShares: number;
  /** 预计到账时间 */
  estimatedArrivalAt: number;
  error?: string;
}

/** 到账时效 → 自然日天数(演示环境不做交易日历,按自然日推进) */
export function settlementDays(cycle: SettlementCycle): number {
  return cycle === "T+0" ? 0 : cycle === "T+1" ? 1 : 2;
}

/**
 * 赎回金额展开。
 *
 * ★ 必须校验的三件事(每一件都对应一类真实客诉):
 *   ① 持有份额是否够(部分赎回 vs 全部赎回);
 *   ② 是否已满最短持有期(未满就赎会被收费或被拒);
 *   ③ 剩余份额是否低于产品保留门槛(部分赎回后剩一点点,管理上不合理)。
 */
export function computeRedemption(input: {
  product: WealthProduct;
  holding: WealthHolding;
  shares?: number;
  amount?: number;
  now: number;
}): RedemptionMath {
  const { product, holding, now } = input;
  const arrival = now + settlementDays(product.settlement) * 24 * 3600 * 1000;
  const base: RedemptionMath = {
    shares: 0,
    grossAmount: 0,
    fee: 0,
    netAmount: 0,
    realizedProfit: 0,
    remainingShares: holding.shares,
    estimatedArrivalAt: arrival,
  };

  if (!product.redeemable) {
    return { ...base, error: `「${product.name}」为封闭式产品,持有期内不可赎回` };
  }
  if (product.minHoldingDays > 0 && holding.holdingDays < product.minHoldingDays) {
    return {
      ...base,
      error: `「${product.name}」需持有满 ${product.minHoldingDays} 天才能赎回,您已持有 ${holding.holdingDays} 天`,
    };
  }

  // 份额口径:直接给份额,或按金额折算
  let shares: number;
  if (input.shares != null && input.shares > 0) {
    shares = round2(input.shares);
  } else if (input.amount != null && input.amount > 0) {
    shares = round2(input.amount / product.nav);
  } else {
    return { ...base, error: "请说明要赎回多少份额或多少金额" };
  }

  if (shares > holding.shares + 1e-9) {
    return {
      ...base,
      error: `赎回份额 ${shares} 超过持有份额 ${holding.shares}`,
    };
  }
  shares = Math.min(shares, holding.shares);

  const grossAmount = round2(shares * product.nav);
  const fee = 0; // 演示环境:持有期赎回费为 0;真实系统按持有天数分档
  const netAmount = round2(grossAmount - fee);
  const costOfShares = round2(shares * holding.avgCostNav);
  const realizedProfit = round2(netAmount - costOfShares);
  const remainingShares = round2(holding.shares - shares);

  return {
    shares,
    grossAmount,
    fee,
    netAmount,
    realizedProfit,
    remainingShares,
    estimatedArrivalAt: arrival,
  };
}

// ============================================================================
// 八、风险提示(结构化拼装,不是让模型自由发挥)
// ============================================================================

/**
 * 风险提示语的**唯一生成入口**。
 *
 * ★ 为什么把提示语做成函数而不是让模型"注意措辞":
 *   模型对"生成一句得体的话"极其擅长,对"每次都生成同一句合规的话"并不可靠。
 *   合规文案的要求恰恰是**每次都一样** —— 内容确定、可审计、可追溯版本。
 *   因此这里用模板拼装:任何展示路径(列表、详情、对比、推荐、确认卡)
 *   都必须调用这个函数,而不是自己写一句"理财有风险"。
 */
export const RISK_DISCLOSURE_STANDARD =
  "理财非存款,产品有风险,投资须谨慎。以上信息仅供参考,不构成投资建议;" +
  "历史业绩不代表未来表现,产品收益存在波动,可能产生本金损失。";

/** 用户话语中出现"保本""稳赚"这类诉求时,系统必须给出的正面回应 */
export const NO_GUARANTEE_STATEMENT =
  "★ 需要明确说明:任何理财产品都**不能承诺保本保收益**。" +
  "如果有人向您承诺「保本高收益」「稳赚不赔」,那不是合规的银行理财,请务必警惕。";

/**
 * 检测文本中是否存在违规的收益承诺(用于输出侧校验,见 orchestrator)。
 *
 * ★ 一个必须避开的误报:合规文案本身包含"不保证本金安全""不保证最低收益"
 *   这类**否定式**表述,而它们与被禁止的"保证收益"只差一个字。
 *   如果正则只匹配"保证(本金|收益)",产品自带的合规风险提示会被自己的
 *   合规闸门删掉 —— 那是一个荒谬但真实存在的失败模式:
 *   越是认真写了风险提示的产品,越容易被这段代码误伤。
 *   因此所有模式都要求"保证"前面**不能**是否定词。
 */
export const GUARANTEE_PATTERNS: RegExp[] = [
  /保本保息/,
  /保本保收益/,
  /(?<![不无没未])保证(?:本金|收益|不亏|盈利)/,
  /(?<![不无没未])承诺(?:收益|回报|年化)/,
  /稳赚(?:不赔|不亏)?/,
  /(?:零|无)风险(?:高|稳)(?:收益|回报)/,
  /一定(?:能|会)(?:赚|盈利|保本)/,
  /必(?:赚|涨|盈利)/,
];

/**
 * 输出侧合规校验。
 *
 * ★ 这是"模型说了不该说的话"的最后一道闸门。
 *   返回命中的违规片段,由编排器在响应发出前拦截并替换。
 *   注意拦截方式是**改写并如实告知**,而不是静默丢弃 ——
 *   用户有权知道自己看到的哪句话被系统改过。
 */
export function detectGuaranteeClaim(text: string): string[] {
  const hits: string[] = [];
  for (const p of GUARANTEE_PATTERNS) {
    const m = text.match(p);
    if (m) hits.push(m[0]);
  }
  return [...new Set(hits)];
}

/** 产品列表/推荐场景的提示语 */
export function buildDisclosureSummary(products: WealthProduct[]): string {
  if (products.length === 0) return RISK_DISCLOSURE_STANDARD;
  const levels = [...new Set(products.map((p) => p.riskLevel))].sort(
    (a, b) => riskLevelOrdinal(a) - riskLevelOrdinal(b),
  );
  const levelText = levels.map((l) => `${l}${PRODUCT_RISK_LABELS[l]}`).join("、");
  return `${RISK_DISCLOSURE_STANDARD}\n本列表产品风险等级:${levelText}`;
}

/** 列表渲染(纯文本,渠道不支持富卡片时的降级形态) */
export function renderProductList(products: WealthProduct[]): string[] {
  return products.map((p, i) => {
    const term = p.termDays == null ? "无固定期限" : termLabel(p);
    return (
      `${i + 1}. ${p.name}(${p.productCode})\n` +
      `   风险等级:${p.riskLevel} ${PRODUCT_RISK_LABELS[p.riskLevel]} · ${PRODUCT_TYPE_LABELS[p.type]}\n` +
      `   收益参考:${yieldLabel(p)}\n` +
      `   期限:${term} · 起购:${p.minAmount.toLocaleString("zh-CN")} 元 · 到账:${p.settlement}`
    );
  });
}

/**
 * 关键词高亮:把产品表述中与"保本/收益"相关的措辞统一替换为合规说法。
 *
 * 例:内部数据里可能出现"业绩比较基准",对外必须原样保留这个措辞
 *     (它和"预期收益"是两个法律含义完全不同的词)。
 *     但若模型把它说成"预期收益 3.2%",这里必须改回"业绩比较基准"。
 */
export function normalizeReturnWording(text: string): { text: string; changed: string[] } {
  const changed: string[] = [];
  let out = text;
  const rewrites: Array<[RegExp, string]> = [
    [/预期(年化)?收益(率)?/g, "业绩比较基准"],
    [/预计(年化)?收益(率)?/g, "业绩比较基准"],
    [/年化收益率\s*([\d.]+)%/g, "业绩比较基准 $1%"],
  ];
  for (const [re, to] of rewrites) {
    const m = out.match(re);
    if (m) {
      changed.push(...m);
      out = out.replace(re, to);
    }
  }
  return { text: out, changed };
}

// ============================================================================
// 八·补、到期续接方案(只读;选定也不等于申购)
// ============================================================================

const ROLLOVER_DAY_MS = 24 * 3600 * 1000;
/** 方案只覆盖银行侧到期日落在这个窗口里的持仓 */
export const ROLLOVER_WINDOW_MS = 30 * ROLLOVER_DAY_MS;
/** 方案快照有效期。过期后净值、可售状态都可能变了,不能拿旧序号去登记选择 */
export const ROLLOVER_PLAN_TTL_MS = 30 * 60 * 1000;

export interface RolloverCandidateView {
  productCode: string;
  name: string;
  riskLevel: ProductRiskLevel;
  sameAsHolding: boolean;
  termText: string;
  minAmount: number;
  settlementText: string;
  yieldText: string;
  drawdownText: string;
}

export interface RolloverExclusion {
  productCode: string;
  name: string;
  reason: string;
}

export interface RolloverPlanView {
  planId: string;
  holdingId: string;
  productCode: string;
  productName: string;
  riskLevel: ProductRiskLevel;
  marketValue: number;
  maturityAt: number;
  daysUntil: number;
  disposition: MaturityDisposition | null;
  dispositionText: string;
  /** 以后若申购,金额口径用的是这笔市值,而且现在并不冻结 */
  amountBasis: number;
  demandAnnualRatePct: number;
  demandRateText: string;
  sourceYieldText: string;
  candidates: RolloverCandidateView[];
  excluded: RolloverExclusion[];
  /** 结构上恒为 false:生成方案不申购 */
  executed: false;
  summary: string;
}

export type RolloverPlanResult =
  | { ok: true; plan: RolloverPlanView }
  | { ok: false; summary: string };

export type RolloverChoiceParse = { kind: "stay_demand" } | { kind: "renew"; index: number };

export interface RolloverFundGate {
  ready: boolean;
  code: "awaiting_maturity" | "still_held" | "short_balance" | "auto_rollover" | "ready" | "unknown_disposition";
  message: string;
}

function rolloverPlanKey(raw: string): string {
  let h = 2166136261;
  for (let i = 0; i < raw.length; i++) {
    h ^= raw.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `RP-${(h >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

function ymd(ts: number): string {
  const d = new Date(ts);
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${m}-${day}`;
}

function yuan(n: number): string {
  return n.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

export function drawdownText(d: MaxDrawdown6m | null | undefined): string {
  if (d == null || !Number.isFinite(d.pct)) return "近 6 个月最大回撤:未披露";
  return `近 6 个月最大回撤 ${d.pct.toFixed(2)}%`;
}

/** 单只详情里用:百分比、窗口、算法放在同一句 */
export function drawdownDetail(d: MaxDrawdown6m | null | undefined): string {
  if (d == null || !Number.isFinite(d.pct)) return "近 6 个月最大回撤:未披露";
  return `近 6 个月最大回撤 ${d.pct.toFixed(2)}%(${ymd(d.windowStart)} 至 ${ymd(d.windowEnd)},${d.method})`;
}

/**
 * 续接对话每轮结尾都给同一类口令。
 * 客户看完要知道下一句说什么;这些口令都有对应的下一轮回答。
 */
export function rolloverFollowUps(stage: "browse" | "renew" | "stay"): string {
  if (stage === "renew") {
    return [
      "接下来可以直接说:",
      "1. 「第2个怎么样」再看一只",
      "2. 「续接第2个」改选,现在仍不买",
      "3. 「不续投」改成留在活期",
    ].join("\n");
  }
  if (stage === "stay") {
    return [
      "接下来可以直接说:",
      "1. 「续接第1个」改成续接,现在仍不买",
      "2. 「第2个怎么样」再看一只",
      "3. 「为什么没放固收」看没进列表的原因",
    ].join("\n");
  }
  return [
    "接下来可以直接说:",
    "1. 「第2个怎么样」看期限、费率和回撤",
    "2. 「第1个和第2个比一下」并排比较",
    "3. 「为什么没放固收」看没进列表的原因",
    "4. 「续接第1个」只登记,现在不买",
    "5. 「不续投」到期后留在活期",
  ].join("\n");
}

function dispositionText(d: MaturityDisposition | null | undefined): string {
  if (d === "to_demand") return "到期后回到活期,不会自动买入下一只产品。";
  if (d === "auto_rollover") return "到期后按原产品自动续期。什么都不做就会续上;要换产品,得先取消自动续期。";
  if (d === "customer_instruction") return "到期后必须由您给出指令,否则按产品说明书处理。银行没有告诉我「什么都不做」的默认去向。";
  return "银行没有给出到期后的资金去向,方案里不能把它说成会回到活期。";
}

function indexFromToken(token: string): number | null {
  if (/^\d+$/.test(token)) {
    const n = Number(token);
    return n >= 1 && n <= 20 ? n : null;
  }
  const cn: Record<string, number> = { 一: 1, 二: 2, 两: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9 };
  if (token === "十") return 10;
  if (token.length === 2 && token.startsWith("十")) {
    const rest = cn[token[1] ?? ""];
    return rest ? 10 + rest : null;
  }
  return cn[token] ?? null;
}

/**
 * 「续接第2个」「不续投」是选择口令,不是申购口令。
 * 光说「第2个」不算选择 —— 那只是在指列表里的一只产品。
 */
export function parseRolloverChoice(text: string): RolloverChoiceParse | null {
  const renew = text.match(/续接\s*第?\s*([0-9一二两三四五六七八九十]+)/);
  const renewTail = text.match(/第\s*([0-9一二两三四五六七八九十]+)\s*个?\s*续接/);
  const token = renew?.[1] ?? renewTail?.[1];
  if (token) {
    const index = indexFromToken(token);
    if (index) return { kind: "renew", index };
  }
  if (/(不续投|留在活期|放到活期|放在活期|不续了)/.test(text)) return { kind: "stay_demand" };
  return null;
}

/**
 * 资金还在份额里,或还没到到期日,就不能申购。
 * 活期里另有余额也不行:那是别的钱,续接不能顺手冻走。
 */
export function evaluateRolloverFunds(input: {
  now: number;
  maturityAt: number;
  disposition: MaturityDisposition | null | undefined;
  /** 银行核心已经把到期资金记入活期 */
  credited: boolean;
  availableBalance: number;
  amount: number;
}): RolloverFundGate {
  if (input.disposition == null) {
    return {
      ready: false,
      code: "unknown_disposition",
      message: "银行没有说明这笔到期后去哪,不能替您申购。",
    };
  }
  if (input.disposition === "auto_rollover") {
    return {
      ready: false,
      code: "auto_rollover",
      message: "这笔到期后会自动续期。在取消自动续期之前,不能再申购另一只,否则可能变成两笔。",
    };
  }
  if (input.now < input.maturityAt) {
    const days = Math.ceil((input.maturityAt - input.now) / ROLLOVER_DAY_MS);
    return {
      ready: false,
      code: "awaiting_maturity",
      message: `还有 ${days} 天到期,钱还在这只产品里,现在不买。`,
    };
  }
  if (!input.credited) {
    return {
      ready: false,
      code: "still_held",
      message: "银行还没把到期款记入活期,现在不买。",
    };
  }
  if (!(input.availableBalance >= input.amount)) {
    return {
      ready: false,
      code: "short_balance",
      message: "到期资金还没有以足额回到可用余额,不能按续接方案申购。",
    };
  }
  return {
    ready: true,
    code: "ready",
    message: "到期款已回到活期。说「按续接方案申购」才进入确认,这句本身不买。",
  };
}

function yieldBasisText(p: WealthProduct): string {
  return yieldLabel(p);
}

/**
 * 选出不高于 min(原产品等级, 客户可买上限) 的在售产品。
 * 不按收益排序。同一风险档里,期限更接近原产品的排前面。
 */
export function buildRolloverPlan(input: {
  customerId: string;
  holdings: WealthHolding[];
  products: WealthProduct[];
  profile: WealthRiskProfile;
  rate: DemandDepositRate;
  now: number;
}): RolloverPlanResult {
  const maturing = input.holdings
    .filter((h) => h.maturityAt != null)
    .filter((h) => {
      const at = h.maturityAt!;
      return at - input.now <= ROLLOVER_WINDOW_MS && input.now - at <= ROLLOVER_DAY_MS;
    })
    .sort((a, b) => a.maturityAt! - b.maturityAt!);

  const holding = maturing[0];
  if (!holding || holding.maturityAt == null) {
    return {
      ok: false,
      summary:
        "目前没有银行侧登记了到期日、且落在 30 天内的理财持仓。" +
        "没有固定期限的产品不会出现在这里。我没有编一个到期日,也没有推荐产品。",
    };
  }

  const source = input.products.find((p) => p.productCode === holding.productCode) ?? null;
  const customerCap =
    input.profile.assessed && !input.profile.expired && input.profile.maxProductRiskLevel
      ? riskLevelOrdinal(input.profile.maxProductRiskLevel)
      : null;
  const sourceCap = riskLevelOrdinal(holding.riskLevel);
  const cap = customerCap == null ? sourceCap : Math.min(customerCap, sourceCap);
  const amount = holding.marketValue;

  const excluded: RolloverExclusion[] = [];
  const eligible: WealthProduct[] = [];
  for (const p of input.products) {
    if (p.status !== "on_sale") {
      if (p.status === "suspended" || p.status === "sold_out") {
        excluded.push({ productCode: p.productCode, name: p.name, reason: "当前不可申购" });
      }
      continue;
    }
    if (riskLevelOrdinal(p.riskLevel) > cap) {
      excluded.push({
        productCode: p.productCode,
        name: p.name,
        reason: `风险 ${p.riskLevel} 高于本次上限 R${cap}`,
      });
      continue;
    }
    if (p.minAmount > amount) {
      excluded.push({
        productCode: p.productCode,
        name: p.name,
        reason: `起购 ${yuan(p.minAmount)} 元,高于这笔到期市值 ${yuan(amount)} 元`,
      });
      continue;
    }
    eligible.push(p);
  }

  const sourceTerm = source?.termDays ?? null;
  eligible.sort((a, b) => {
    const riskD = (p: WealthProduct) => Math.abs(riskLevelOrdinal(p.riskLevel) - sourceCap);
    const termD = (p: WealthProduct) => {
      if (sourceTerm == null && p.termDays == null) return 0;
      if (sourceTerm == null || p.termDays == null) return 10_000;
      return Math.abs(p.termDays - sourceTerm);
    };
    return riskD(a) - riskD(b) || termD(a) - termD(b) || a.productCode.localeCompare(b.productCode);
  });

  const picked = eligible.slice(0, 3);
  const candidates: RolloverCandidateView[] = picked.map((p) => ({
    productCode: p.productCode,
    name: p.name,
    riskLevel: p.riskLevel,
    sameAsHolding: p.productCode === holding.productCode,
    termText: p.termDays == null ? "无固定期限" : termLabel(p),
    minAmount: p.minAmount,
    settlementText: p.settlement,
    yieldText: yieldBasisText(p),
    drawdownText: drawdownText(p.maxDrawdown6m),
  }));

  const daysUntil = Math.ceil((holding.maturityAt - input.now) / ROLLOVER_DAY_MS);
  const disposition = holding.maturityDisposition ?? null;
  const demandRateText =
    `${input.rate.accountTypeLabel}挂牌年利率 ${input.rate.annualRatePct.toFixed(2)}%` +
    `(生效日 ${ymd(input.rate.effectiveFrom)},来源:${input.rate.source})`;
  const sourceYieldText = source ? yieldBasisText(source) : "原产品业绩口径未在目录中";
  const planId = rolloverPlanKey(
    [
      input.customerId,
      holding.holdingId,
      String(holding.maturityAt),
      amount.toFixed(2),
      input.rate.annualRatePct.toFixed(4),
      String(cap),
      candidates.map((c) => c.productCode).join(","),
    ].join("|"),
  );

  const when = daysUntil <= 0 ? "今天到期" : `${daysUntil} 天后到期`;
  const lines: string[] = [];
  lines.push(`到期续接方案 · ${holding.productName} ${when}(${ymd(holding.maturityAt)})`);
  lines.push(
    `市值约 ${yuan(holding.marketValue)} 元(估值)。${dispositionText(disposition)}只比较,不会申购,也不按收益排序,也不给综合最优。`,
  );
  if (maturing.length > 1) {
    lines.push(`另有 ${maturing.length - 1} 笔也在 30 天内,这次只处理最近一笔。`);
  }
  lines.push("");
  if (candidates.length === 0) {
    lines.push("没有同时满足风险上限和起购金额的在售产品。");
  }
  candidates.forEach((c, i) => {
    const same = c.sameAsHolding ? "(同一只,仍在售)" : "";
    lines.push(`${i + 1}. ${c.name}${same} · ${c.riskLevel} · ${c.yieldText} · ${c.drawdownText} · ${c.termText}`);
  });
  lines.push("");
  lines.push(`不续投:${demandRateText}。原产品:${sourceYieldText}。口径不同,不能相减。`);
  if (customerCap == null) {
    lines.push("您还没完成风险测评。真正申购时要先测评。");
  }
  lines.push(RISK_DISCLOSURE_STANDARD);
  lines.push("");
  lines.push(rolloverFollowUps("browse"));

  const plan: RolloverPlanView = {
    planId,
    holdingId: holding.holdingId,
    productCode: holding.productCode,
    productName: holding.productName,
    riskLevel: holding.riskLevel,
    marketValue: holding.marketValue,
    maturityAt: holding.maturityAt,
    daysUntil,
    disposition,
    dispositionText: dispositionText(disposition),
    amountBasis: amount,
    demandAnnualRatePct: input.rate.annualRatePct,
    demandRateText,
    sourceYieldText,
    candidates,
    excluded,
    executed: false,
    summary: lines.join("\n"),
  };
  return { ok: true, plan };
}

/**
 * 「预计年化下降 X%」这类落差口号。
 * 活期利率和理财历史业绩不能相减后说成客户将少拿的钱。
 */
export const YIELD_GAP_PATTERNS: RegExp[] = [
  /预计.{0,16}(下降|降低|少赚|落差)/,
  /年化收益下降/,
  /收益落差/,
  /少赚/,
  /转出至活期.{0,24}(下降|少)/,
];

export function detectYieldGapClaim(text: string): string[] {
  const hits: string[] = [];
  for (const p of YIELD_GAP_PATTERNS) {
    const m = text.match(p);
    if (m) hits.push(m[0]);
  }
  return [...new Set(hits)];
}

// ============================================================================
// 九、工具
// ============================================================================

/**
 * ★ 这几个格式化函数已收归 `util/format.ts` 一份实现。
 *   这里保留同名 re-export:调用方的导入路径不变,但"改一处漏六处"的风险没有了
 *   (原来 `fmtMoney` 在仓库里有 7 份逐字相同的拷贝)。
 */
export { fmtDay, fmtMoney, round2 } from "../util/format.ts";
// 本文件内部只用到 round2;fmtDay / fmtMoney 仅作为对外 re-export 保留(调用方导入路径不变)
import { round2 } from "../util/format.ts";

export function fmtPct(n: number): string {
  return `${n >= 0 ? "+" : ""}${n.toFixed(2)}%`;
}

/** 持有期文案 */
export function holdingDaysLabel(days: number): string {
  if (days < 1) return "当日买入";
  if (days < 30) return `${days} 天`;
  if (days < 365) return `${Math.floor(days / 30)} 个月`;
  return `${(days / 365).toFixed(1)} 年`;
}

/** App 端逐题风评卡:第 stepIndex 题(0 起)。 */
export function riskAssessmentQuizVisual(stepIndex: number): QuizStepVisual | null {
  const q = ASSESSMENT_QUESTIONS[stepIndex];
  if (!q) return null;
  const n = stepIndex + 1;
  const total = ASSESSMENT_QUESTIONS.length;
  return {
    kind: "quiz_step",
    title: "风险承受能力测评",
    progress: `第 ${n} / ${total} 题`,
    question: q.question,
    options: q.options.map((o) => ({
      optionId: o.optionId,
      label: `${o.optionId.toUpperCase()}. ${o.label}`,
      say: o.optionId,
    })),
    compactBody: `第 ${n}/${total} 题:点选一项即可。`,
  };
}
