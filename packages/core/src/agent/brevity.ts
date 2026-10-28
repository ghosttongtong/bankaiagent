/**
 * 客户可见文本的精简(Brevity)
 *
 * ★ 为什么需要一个独立的精简层,而不是"把每个能力的文案都改短":
 *
 *   项目里大量文案是写给**评审与维护者**看的 ——
 *   "★ 这不是我偷懒:账户接管最常见的路径就是……"、
 *   "★ 这不是在拒绝你,而是确保你在知情的前提下自己决定"、
 *   "实测中踩到过……"。
 *   这些话在一个 400 行的设计文档里非常有价值,在客户的聊天窗口里则是噪音:
 *   客户只想知道**能不能办、怎么买、要交什么**。
 *
 *   把它们逐条从各能力里删掉既费力又会丢失设计说明(那些注释本身是资产)。
 *   所以这里做的是**输出侧过滤**:能力照旧写它的完整说明(进审计、进文档),
 *   发给客户的那份在出口处收一遍。
 *
 * ★ 三条不可越过的红线(实测踩过的代价):
 *   ① **只删元说明,不删事实。** 「申请 ≠ 已生效」「5 个工作日到手」「密码沿用」
 *      这类是客户必须知道的事实,无论多啰嗦都不能删 —— 一旦删掉,
 *      系统就会在客户问"我的额度提了吗"时答不上来。
 *   ② **不删警示与合规话术。** 反诈提示、风险揭示、可撤销窗口都属于此类。
 *   ③ **删了什么要留痕。** 被删掉的句子进审计(payload.removedLines),
 *      这样"系统给客户看的是精简版"这件事是可复核的,而不是悄悄改写。
 */

/** 只匹配"明确写给开发者/评委"的句子。宁少删,不多删。 */
const META_PATTERNS: RegExp[] = [
  /这不是我偷懒/,
  /这不是在拒绝[你您]/,
  /不是在拒绝[你您],而是/,
  /本项目的?设计/,
  /设计取舍/,
  /答辩/,
  /演示时/,
  /为了方便演示/,
  /实测中?(踩|报|发现)/,
  /踩过(这个)?坑/,
  /课程/,
  /评委/,
];

/**
 * 判定一行是不是"元说明"。
 *
 * ★ 只看以 ★ / ※ / 注: 开头的行 —— 这是项目里书写"内部说明"的既有约定。
 *   正文段落里出现"实测"之类的词不动它:那可能正是客户要听的解释。
 */
function isMetaLine(line: string): boolean {
  const t = line.trim();
  if (!t) return false;
  if (!/^[★※]|^注[:：]/.test(t)) return false;
  return META_PATTERNS.some((re) => re.test(t));
}

/**
 * 精简一段面向客户的文本。
 *
 * 处理顺序:去元说明行 → 去连续重复行 → 折叠多余空行 → 收尾空白。
 */
export function condenseForCustomer(text: string): { text: string; removed: string[] } {
  const removed: string[] = [];
  const input = String(text ?? "");

  // ① 去元说明行(整行删除,不做半句截断 —— 半句话比啰嗦更糟)
  const kept: string[] = [];
  for (const line of input.split("\n")) {
    if (isMetaLine(line)) {
      removed.push(line.trim());
      continue;
    }
    kept.push(line);
  }

  // ② 去连续重复行(同一条提示被两个环节各写一遍时很常见)
  const dedup: string[] = [];
  for (const line of kept) {
    const prev = dedup[dedup.length - 1];
    if (line.trim() && prev !== undefined && line.trim() === prev.trim()) {
      removed.push(line.trim());
      continue;
    }
    dedup.push(line);
  }

  // ③ 折叠 3 行以上空行为 1 行空行
  const out: string[] = [];
  let blank = 0;
  for (const line of dedup) {
    if (line.trim() === "") {
      blank += 1;
      if (blank > 1) continue;
      out.push("");
    } else {
      blank = 0;
      out.push(line.replace(/\s+$/, ""));
    }
  }

  return { text: out.join("\n").trim(), removed };
}
