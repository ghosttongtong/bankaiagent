/**
 * 位置指代(Positional Reference)—— 「第1个」「第3只」「前两个」「1和3」
 *
 * ★ 为什么单独成文件:这个能力有两个使用方,而它们的依赖方向必须都指向 core ——
 *   ① **离线解析器**(`llm/deterministic.ts`)用它填 `intent.wealth.ordinalRefs`;
 *   ② **编排器**(`core/agent/orchestrator.ts`)用它处理"整句就是一个序号"
 *      的裸指代(「第2个怎么样」)与"哪个列表"的解析。
 *
 *   如果放在 orchestrator.ts 里,llm 层 import orchestrator 会连带拉起整个主循环;
 *   如果放在 deterministic.ts 里,则变成 core import llm —— 把分层彻底倒过来。
 *   单独一层谁都不依赖的小模块,是唯一不破坏依赖方向的做法。
 *
 * ★ 这一类指代为什么值得专门建模:
 *   用户看过一份产品列表之后,**最自然的指代方式就是位置** ——
 *   「第1个和第3个对比一下」「第2个怎么样」「前两个哪个好」。
 *   它说的不是产品名,而是"你说的那份列表里的第几个"。
 *   因此它的语义**完全依赖"刚才展示的是哪份列表"**,
 *   必须由系统拿会话里记住的列表去解 ——
 *   任何试图在这一层把序号直接翻译成产品名的做法都是在编造。
 */

export interface OrdinalRef {
  kind: "indices" | "first_n";
  /** kind=indices:从 1 开始的序号(与用户看到的编号一致) */
  indices: number[];
  /** kind=first_n:前 n 个 */
  n: number;
}

/**
 * 抽取位置指代。
 *
 * ★ 判据取舍(两个方向都要小心):
 *   · 太松 → 「我有5万块」里的 5 会被当成"第 5 个产品";
 *   · 太紧 → 「第一个和第三个」这种最自然的说法反而接不住。
 *
 *   因此区分两类写法,给不同强度的判据:
 *     ① **带标记的序号**(「第1个」「第3只」「前两个」)——
 *        标记词本身就说明用户在指代列表位置,可以放心取数;
 *     ② **裸数字**(「1和3比一下」)——
 *        只有当数字被"和/与/、/跟"串起来、**且句子里有对比语境**时才认。
 *        单独一个数字(「5」)仍按金额处理,那是更常见的含义,不能被抢走。
 */
export function extractOrdinalRefs(text: string): OrdinalRef[] {
  const out: OrdinalRef[] = [];
  const t = text.trim();

  // ⓪ ★ 整句就是一个裸序号:「4」「12」
  //
  //   ★ 这是一个低级但致命的遗漏。用户看完一份编号列表,最直接的回复就是
  //     回那个编号本身 —— 「4」。而原来的判据只认「第4个」「前两个」,
  //     单独的「4」一个分支都进不去,于是它落到"没有位置指代"那条路,
  //     最后被当成金额(¥4)去追问收款人。
  //
  //   同时这也解释了另一个看起来更荒谬的现象:同一次会话里,
  //   系统明明列出了 5 项,用户回「4」却被回答"超出列表范围" ——
  //   因为它压根没把「4」当成序号,而是走了别的分支。
  //   (修复时我把两处一起改了:裸序号要能被识别,越界说明也要报出用户说的序号。)
  const wholeNumber = t.match(/^([0-9]{1,2})$/);
  if (wholeNumber) {
    out.push({ kind: "indices", indices: [Number(wholeNumber[1])], n: 0 });
    return out;
  }

  // ① ★「4. 固收+双利180天(LC2001)」—— 用户把整行**照抄**回来
  //
  //   这是列表交互里极其自然的一种回复:屏幕上就是「4. 名字(代码)」,
  //   用户直接复制粘贴或照着念。此时序号与产品名**同时给出**,
  //   序号最可靠(它直接对应我们打印的编号),因此优先按序号解。
  const listLine = t.match(/^([0-9]{1,2})\s*[.、、)):：]\s*(.+)$/);
  if (listLine) {
    out.push({ kind: "indices", indices: [Number(listLine[1])], n: 0 });
    return out;
  }

  // ② 「前两个」「前3只」
  const firstN = t.match(/前\s*([0-9]+|[一二两三四五六七八九十]+)\s*(?:个|只|支|款|种)?/);
  if (firstN?.[1]) {
    const raw = firstN[1]!;
    const n = /^[0-9]+$/.test(raw) ? Number(raw) : (cnNumberToInt(raw) ?? 0);
    if (n >= 2 && n <= 10) out.push({ kind: "first_n", indices: [], n });
  }

  // ③ 「第1个」「第一个」「第 3 只」
  const markedIndices: number[] = [];
  for (const m of t.matchAll(/第\s*([0-9]+|[一二两三四五六七八九十]+)\s*(?:个|只|支|款|种)?/g)) {
    const raw = m[1]!;
    const v = /^[0-9]+$/.test(raw) ? Number(raw) : cnNumberToInt(raw);
    if (v != null && v >= 1 && v <= 20) markedIndices.push(v);
  }
  if (markedIndices.length > 0) {
    out.push({ kind: "indices", indices: [...new Set(markedIndices)], n: 0 });
  } else {
    // ④ 裸数字被连接词串起来:「1和3」「1、3」「1跟3」
    //
    // ★ 这一类**不要求出现对比词**。曾经加过 `hasCompareCue` 这个门槛,
    //   本意是怕把金额当成序号,但实测发现它把最自然的一种说法挡在了外面:
    //   「1和3比一下」—— 用户就是用"比一下"表达对比的,而那个词
    //   恰恰不在对比词表里("比一下"不是"对比"也不是"比较")。
    //
    //   真正的护栏不是"有没有对比词",而是这两条:
    //     ① 数字必须被「和/与/跟/、/,/及」**串起来**(单独一个 5 不算);
    //     ② 只认一位数(1–9)。
    //   金额几乎不会写成「1和3」这种形状,再加上路由层还会校验
    //   "序号是否在刚展示的列表范围内",漏判与误判都被兜住了。
    const bare = t.match(
      /(?:^|[^\d])([1-9])\s*(?:和|与|跟|、|,|及)\s*([1-9])(?:\s*(?:和|与|跟|、|,|及)\s*([1-9]))?/,
    );
    if (bare) {
      const nums = [bare[1], bare[2], bare[3]]
        .filter((s): s is string => Boolean(s))
        .map(Number)
        .filter((v) => v >= 1 && v <= 20);
      if (nums.length >= 2) out.push({ kind: "indices", indices: [...new Set(nums)], n: 0 });
    }
  }

  return out;
}

/**
 * 中文数字 → 整数(覆盖 1–99,位置指代够用)。
 *
 * 刻意不复用 llm 层的金额解析器:那个函数要处理"五万三"这类复杂形态,
 * 而这里只需要"三""十一""二十"这种简单序号。职责清楚、互不牵连 ——
 * 更重要的是:不复用就不会为了一个位置指代把金额解析的 bug 面引进来。
 */
export function cnNumberToInt(s: string): number | null {
  const DIGITS: Record<string, number> = {
    一: 1, 二: 2, 两: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9,
  };
  if (s === "十") return 10;
  if (/^十[一二三四五六七八九]$/.test(s)) return 10 + DIGITS[s[1]!]!;
  if (/^[一二两三四五六七八九]十$/.test(s)) return DIGITS[s[0]!]! * 10;
  if (/^[一二两三四五六七八九]十[一二三四五六七八九]$/.test(s)) {
    return DIGITS[s[0]!]! * 10 + DIGITS[s[2]!]!;
  }
  return DIGITS[s] ?? null;
}

/**
 * 整句是不是"一个纯位置指代"(如「第2个」「2」「第二个怎么样」)?
 *
 * ★ 用途:用户在列表后可能**不带动词**地指某一只 —— 「第2个怎么样」。
 *   这类句子在解析器里会掉进转账分支(「第」字被当成收款人,回一句
 *   "这笔要转多少钱"),必须在正常解析之前接住,并当成
 *   "选列表里的第 2 个"处理。
 *
 * ★ 为什么只认单个数字(`^[1-9]$`):两个及以上数字更可能是金额,
 *   而"列表里第 12 个"这种说法真实对话里几乎不出现。宁可漏接,
 *   也不能把用户说的金额抢走当成序号。
 */
export function isBareOrdinalReference(text: string): boolean {
  const t = text.trim().replace(/[。!?!?,,\s]+$/g, "");
  if (t.length === 0 || t.length > 14) return false;
  if (
    /^第\s*(?:[0-9]+|[一二两三四五六七八九十]+)\s*(?:个|只|支|款|种)?\s*(?:怎么样|呢|如何|的?(?:详情|情况|资料))?$/.test(
      t,
    )
  ) {
    return true;
  }
  if (/^[1-9]$/.test(t)) return true;
  return false;
}
