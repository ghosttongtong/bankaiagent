/**
 * 姓名模糊匹配引擎
 *
 * ★ 目标:让"用户怎么念,系统就怎么认"。
 *
 * 真实用户输入姓名时会有四类偏差:
 *   ① 错别字       「张玮」→ 张伟(同音形近字,最常见)
 *   ② 拼音输入     「zhangwei」/「zw」→ 张伟
 *   ③ 口头称呼     「老王」「小陈」→ 王秀兰 / 陈建国(前缀+姓)
 *   ④ 记忆偏差     「张伟明」→ 张伟(多说了字)
 *
 * 之前只做"精确 + 包含"匹配,四类全都落到"未找到,请确认姓名"。
 * 现在补齐:编辑距离 + 姓氏同音表 + 拼音首字母 + 称呼前缀剥离。
 *
 * 设计取舍:
 *   - 不引入拼音库。只维护**姓氏**的拼音表(覆盖百家姓前 100),
 *     因为中国姓名的辨识度高度集中在姓氏上,而且用户打错字大概率在名而非姓。
 *     这能覆盖绝大多数场景,同时保持零依赖。
 *   - **所有模糊匹配都必须经过澄清确认**,绝不直接执行。
 *     打分只用于排序候选,不用于"决定是谁"。这是转错人风险的底线。
 */

// ============================================================================
// 拼音表(姓氏部分,覆盖百家姓前 100)
// ============================================================================

/**
 * 常见姓氏的拼音。只覆盖姓氏是有意为之:
 * 姓名辨识度集中在姓氏,维护成本却低一个数量级。
 */
const SURNAME_PINYIN: Record<string, string> = {
  赵: "zhao", 钱: "qian", 孙: "sun", 李: "li", 周: "zhou", 吴: "wu", 郑: "zheng", 王: "wang",
  冯: "feng", 陈: "chen", 褚: "chu", 卫: "wei", 蒋: "jiang", 沈: "shen", 韩: "han", 杨: "yang",
  朱: "zhu", 秦: "qin", 尤: "you", 许: "xu", 何: "he", 吕: "lv", 施: "shi", 张: "zhang",
  孔: "kong", 曹: "cao", 严: "yan", 华: "hua", 金: "jin", 魏: "wei", 陶: "tao", 姜: "jiang",
  戚: "qi", 谢: "xie", 邹: "zou", 喻: "yu", 柏: "bai", 水: "shui", 窦: "dou", 章: "zhang",
  云: "yun", 苏: "su", 潘: "pan", 葛: "ge", 奚: "xi", 范: "fan", 彭: "peng", 郎: "lang",
  鲁: "lu", 韦: "wei", 昌: "chang", 马: "ma", 苗: "miao", 凤: "feng", 花: "hua", 方: "fang",
  俞: "yu", 任: "ren", 袁: "yuan", 柳: "liu", 唐: "tang", 罗: "luo", 薛: "xue", 伍: "wu",
  余: "yu", 米: "mi", 贝: "bei", 姚: "yao", 孟: "meng", 顾: "gu", 尹: "yin", 江: "jiang",
  钟: "zhong", 沈2: "shen", 邱: "qiu", 骆: "luo", 高: "gao", 夏: "xia", 蔡: "cai", 田: "tian",
  胡: "hu", 凌: "ling", 霍: "huo", 虞: "yu", 万: "wan", 支: "zhi", 柯: "ke", 昝: "zan",
  管: "guan", 卢: "lu", 莫: "mo", 房: "fang", 裘: "qiu", 缪: "miao", 干: "gan", 解: "xie",
  应: "ying", 宗: "zong", 丁: "ding", 宣: "xuan", 邓: "deng", 郁: "yu", 单: "shan", 杭: "hang",
  洪: "hong", 包: "bao", 诸: "zhu", 左: "zuo", 石: "shi", 崔: "cui", 吉: "ji", 龚: "gong",
  程: "cheng", 邢: "xing", 裴: "pei", 陆: "lu", 荣: "rong", 翁: "weng", 荀: "xun", 羊: "yang",
  甄: "zhen", 曲: "qu", 封: "feng", 芮: "rui", 储: "chu", 靳: "jin", 汲: "ji", 邴: "bing",
  糜: "mi", 松: "song", 井: "jing", 段: "duan", 富: "fu", 巫: "wu", 乌: "wu", 焦: "jiao",
  巴: "ba", 弓: "gong", 牧: "mu", 隗: "kui", 山: "shan", 谷: "gu", 车: "che", 侯: "hou",
  宓: "mi", 蓬: "peng", 全: "quan", 郗: "xi", 班: "ban", 仰: "yang", 秋: "qiu", 仲: "zhong",
  伊: "yi", 宫: "gong", 宁: "ning", 仇: "qiu", 栾: "luan", 暴: "bao", 甘: "gan", 斜: "xie",
  厉: "li", 戎: "rong", 祖: "zu", 武: "wu", 符: "fu", 刘: "liu", 景: "jing", 詹: "zhan",
  束: "shu", 龙: "long", 叶: "ye", 幸: "xing", 司: "si", 韶: "shao", 郜: "gao", 黎: "li",
  蓟: "ji", 薄: "bo", 印: "yin", 宿: "su", 白: "bai", 怀: "huai", 蒲: "pu", 邰: "tai",
  从: "cong", 鄂: "e", 索: "suo", 咸: "xian", 籍: "ji", 赖: "lai", 卓: "zhuo", 蔺: "lin",
  屠: "tu", 蒙: "meng", 池: "chi", 乔: "qiao", 阴: "yin", 胥: "xu", 能: "neng", 苍: "cang",
  双: "shuang", 闻: "wen", 莘: "shen", 党: "dang", 翟: "zhai", 谭: "tan", 贡: "gong", 劳: "lao",
  逄: "pang", 姬: "ji", 申: "shen", 扶: "fu", 堵: "du", 冉: "ran", 宰: "zai", 郦: "li",
  雍: "yong", 却: "que", 璩: "qu", 桑: "sang", 桂: "gui", 濮: "pu", 牛: "niu", 寿: "shou",
  通: "tong", 边: "bian", 扈: "hu", 燕: "yan", 冀: "ji", 浦: "pu", 尚: "shang", 农: "nong",
  温: "wen", 别: "bie", 庄: "zhuang", 晏: "yan", 柴: "chai", 瞿: "qu", 阎: "yan", 充: "chong",
  慕: "mu", 连: "lian", 茹: "ru", 习: "xi", 宦: "huan", 艾: "ai", 鱼: "yu", 容: "rong",
  向: "xiang", 古: "gu", 易: "yi", 慎: "shen", 戈: "ge", 廖: "liao", 庾: "yu", 终: "zhong",
  暨: "ji", 居: "ju", 衡: "heng", 步: "bu", 都: "du", 耿: "geng", 满: "man", 弘: "hong",
  匡: "kuang", 国: "guo", 文: "wen", 寇: "kou", 广: "guang", 禄: "lu", 阙: "que", 东: "dong",
  欧: "ou", 殳: "shu", 沃: "wo", 利: "li", 蔚: "wei", 越: "yue", 夔: "kui", 隆: "long",
  师: "shi", 巩: "gong", 厍: "she", 聂: "nie", 晁: "chao", 勾: "gou", 敖: "ao", 融: "rong",
  冷: "leng", 訾: "zi", 辛: "xin", 阚: "kan", 那: "na", 简: "jian", 饶: "rao", 空: "kong",
  曾: "zeng", 毋: "wu", 沙: "sha", 乜: "nie", 养: "yang", 鞠: "ju", 须: "xu", 丰: "feng",
  巢: "chao", 关: "guan", 蒯: "kuai", 相: "xiang", 查: "zha", 後: "hou", 荆: "jing",
  红: "hong", 游: "you", 竺: "zhu", 权: "quan", 逯: "lu", 盖: "gai", 益: "yi", 桓: "huan",
  公: "gong", 欧阳: "ouyang", 司马: "sima", 上官: "shangguan", 诸葛: "zhuge",
};

/** 取姓氏的拼音(支持复姓)。取不到时返回 null。 */
export function surnamePinyin(name: string): string | null {
  if (name.length === 0) return null;
  // 复姓优先
  if (name.length >= 2) {
    const two = name.slice(0, 2);
    if (SURNAME_PINYIN[two]) return SURNAME_PINYIN[two]!;
  }
  return SURNAME_PINYIN[name[0]!] ?? null;
}

/** 拼音首字母(仅姓氏可用) */
export function surnameInitial(name: string): string | null {
  const p = surnamePinyin(name);
  return p ? p[0]! : null;
}

// ============================================================================
// 编辑距离
// ============================================================================

/** 标准 Levenshtein 距离 */
export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  const curr = new Array<number>(b.length + 1);

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1]! + 1, prev[j]! + 1, prev[j - 1]! + cost);
    }
    prev = [...curr];
  }
  return prev[b.length]!;
}

/** 名称归一化:去掉空白、标点、称呼后缀 */
export function normalizeName(raw: string): string {
  return raw
    .replace(/[\s,,。、·．.]/g, "")
    .replace(/(先生|女士|小姐|老师|经理|总|哥|姐|叔|姨|大爷|大妈)$/g, "")
    .toLowerCase();
}

// ============================================================================
// 打分
// ============================================================================

export interface NameMatchScore {
  /** 0–1,越高越可能 */
  score: number;
  /** 匹配依据(用于向用户解释与审计) */
  basis:
    | "exact"
    | "surname_prefix"
    | "contains"
    | "homophone"
    | "pinyin_prefix"
    | "edit_distance"
    | "none";
  /** 人话说明 */
  explanation?: string;
}

const CALLING_PREFIXES = ["老", "小", "大", "阿"];

/**
 * 计算查询串与目标姓名的匹配分。
 *
 * 打分阶梯(从高到低):
 *   1.00  完全一致
 *   0.92  称呼前缀匹配(「老王」→「王秀兰」);要求目标姓氏一致
 *   0.88  姓名包含关系(「秀兰」→「王秀兰」)
 *   0.85  同音姓氏(「章伟」→「张伟」,zhang 同音)
 *   0.82  拼音首字母匹配(「zw」→「张伟」)
 *   0.55–0.80  编辑距离 1–2(「张玮」→「张伟」)
 *   <0.5  视为不匹配
 */
export function scoreName(query: string, target: string): NameMatchScore {
  const q = normalizeName(query);
  const t = normalizeName(target);

  if (q.length === 0 || t.length === 0) return { score: 0, basis: "none" };

  // 1. 完全一致
  if (q === t) return { score: 1, basis: "exact" };

  // 2. 称呼前缀:「老王」→ 王秀兰
  if (q.length >= 2 && CALLING_PREFIXES.includes(q[0]!) && !CALLING_PREFIXES.includes(t[0]!)) {
    const rest = q.slice(1);
    // 「老王」:姓王;目标姓名以王开头
    if (t.startsWith(rest) || (rest.length === 1 && t[0] === rest)) {
      return { score: 0.92, basis: "surname_prefix", explanation: `「${query}」按姓氏匹配到「${target}」` };
    }
  }

  // 3. 包含关系
  if (t.includes(q)) return { score: 0.88, basis: "contains" };
  if (q.includes(t) && t.length >= 2) return { score: 0.8, basis: "contains" };

  // 4. 同音姓氏:只看姓氏拼音是否相同。
  //    这是「张玮/章伟/张伟」这类错别字的主要成因 —— 拼音输入法选错同音字。
  const qp = surnamePinyin(q);
  const tp = surnamePinyin(t);
  if (qp && tp && qp === tp && q[0] !== t[0]) {
    // 姓氏同音,且剩余部分也比较接近(至少共享一个字符,或编辑距离很小)
    const qRest = q.slice(qp.length >= 6 ? 2 : 1);
    const tRest = t.slice(tp.length >= 6 ? 2 : 1);
    const restDist = editDistance(qRest, tRest);
    if (restDist <= Math.max(1, Math.floor(tRest.length / 2))) {
      return {
        score: 0.85,
        basis: "homophone",
        explanation: `「${query}」与「${target}」姓氏同音(${qp})`,
      };
    }
  }

  // 5. 拼音首字母:「zw」→ 张伟
  const qLower = q.toLowerCase();
  if (/^[a-z]{2,6}$/.test(qLower)) {
    const ti = surnameInitial(t);
    if (ti && qLower.startsWith(ti)) {
      return { score: 0.82, basis: "pinyin_prefix", explanation: `「${query}」按拼音首字母匹配` };
    }
  }

  // 6. 编辑距离(错别字)
  const dist = editDistance(q, t);
  const maxLen = Math.max(q.length, t.length);
  if (dist === 1 && maxLen >= 2) {
    return { score: 0.78, basis: "edit_distance", explanation: `「${query}」与「${target}」相差一个字` };
  }
  if (dist === 2 && maxLen >= 3) {
    return { score: 0.6, basis: "edit_distance", explanation: `「${query}」与「${target}」相差两个字` };
  }

  return { score: 0, basis: "none" };
}

// ============================================================================
// 候选消歧依据
// ============================================================================

/**
 * 判断两段文本是否"同音或形近" —— 供别名学习使用。
 * 比 scoreName 更宽松,因为它不需要区分候选,只需要判断"像不像"。
 */
export function looksSimilar(a: string, b: string): boolean {
  const na = normalizeName(a);
  const nb = normalizeName(b);
  if (na === nb) return true;
  if (na.length === 0 || nb.length === 0) return false;
  if (na.includes(nb) || nb.includes(na)) return true;

  const pa = surnamePinyin(na);
  const pb = surnamePinyin(nb);
  if (pa && pb && pa === pb) return true;

  return editDistance(na, nb) <= 1;
}
