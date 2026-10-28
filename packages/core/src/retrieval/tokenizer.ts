/**
 * 检索分词(中文二元组 + 英文/数字片段)。
 *
 * ★ 为什么不用现成分词库:本项目**零新依赖**(红线 #6)。
 *   而制度问答的查询都很短(「怎么免年费」),中文用**二元组(bigram)**
 *   就足够稳:它不需要词典,也不会因为切错词把"年费"拆成"年/费"而漏检。
 *   代价是索引里的词更多,但语料只有 20 条条款,完全可以接受。
 *
 * ★ 数字与带单位片段必须整体保留:「50万」「T+1」「4.1」「R5」这些是条款的关键,
 *   拆成"5"和"0"就什么也匹配不上了。
 */

/**
 * 停用词。
 *
 * ★ 只放"几乎不承载含义"的词:它们出现在**每一句**话里,
 *   留着只会让 BM25 的分数被稀释(查询词越长,coverage 越难达标)。
 *   刻意**不**放"多久/多少/怎么" —— 这三类恰恰是制度问答的提问核心,
 *   去掉它们会让「赎回多久到账」这种句子失去区分度。
 */
const STOPWORDS = new Set([
  "的",
  "了",
  "吗",
  "呢",
  "吧",
  "啊",
  "呀",
  "哦",
  "嘛",
  "我",
  "你",
  "你们",
  "我们",
  "他",
  "她",
  "它",
  "这个",
  "那个",
  "这些",
  "那些",
  "请问",
  "请",
  "一下",
  "是",
  "是不是",
  "有没有",
  "有",
  "和",
  "与",
  "及",
  "还有",
  "就",
  "都",
  "也",
  "还",
  "要",
  "会",
  "能",
  "可以",
]);

/** 全角 → 半角、去多余空白、英文小写 */
export function normalizeText(text: string): string {
  return String(text ?? "")
    .replace(/[\uFF01-\uFF5E]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 0xfee0))
    .replace(/\u3000/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

/** 词元切分:中文二元组 + 英文/数字整体片段(保留重复,供 BM25 计词频) */
export function tokenize(text: string): string[] {
  const normalized = normalizeText(text);
  if (normalized.length === 0) return [];

  const tokens: string[] = [];
  const push = (tok: string): void => {
    if (tok.length === 0) return;
    if (STOPWORDS.has(tok)) return;
    tokens.push(tok);
  };

  // 中文段 / 英文段 / 数字(可带小数与万/千/百/年/天/元)
  const RE = /[\u4e00-\u9fa5]+|[a-z]+|\d+(?:\.\d+)?(?:万|千|百|年|天|元|个)?/g;
  for (const match of normalized.matchAll(RE)) {
    const piece = match[0];
    if (/^[\u4e00-\u9fa5]+$/.test(piece)) {
      if (piece.length === 1) {
        push(piece);
        continue;
      }
      // 二元组:中文最短的有意义单元
      for (let i = 0; i + 1 < piece.length; i++) push(piece.slice(i, i + 2));
      continue;
    }
    push(piece);
  }
  return tokens;
}

/**
 * 费用类提问的口语说法。
 *
 * ★ 为什么要做这一层"查询侧同义词":
 *   客户问价的方式有十几种(多少钱/贵多少/收钱吗/要钱吗/费用/费率),
 *   而条款里写的通常是"工本费/手续费/收费标准"。纯词面匹配时,
 *   「补卡多少钱」只能命中"补卡",和「补卡要多久」拿到同一批候选 ——
 *   于是价目条款与时限条款挤在一起,系统只能拒答。
 *
 * ★ 只对**查询**做扩展,文档侧不动:
 *   如果两边都扩成"费用",所有收费条款就都长得一样了;
 *   只在查询侧补一个"费用"意向词,既能把价目条款拉上来,
 *   又不会破坏"年费 ≠ 手续费"这类区分(原文的专有词仍在)。
 */
const FEE_QUERY_CUE = /(多少钱|贵多少|收钱|要钱|收费|费用|工本费|手续费|管理费|服务费|年费|费率)/;

/** 查询词集合(去重 + 去停用词 + 费用同义词扩展)—— coverage 的分母 */
export function queryTokens(text: string): string[] {
  const tokens = new Set(tokenize(text));
  if (FEE_QUERY_CUE.test(normalizeText(text))) tokens.add("费用");
  return [...tokens];
}

/** 查一个词元是否出现在某段文本里(用于解释"为什么命中这条") */
export function explainMatched(tokens: string[], text: string): string[] {
  const normalized = normalizeText(text);
  return tokens.filter((t) => normalized.includes(t));
}
