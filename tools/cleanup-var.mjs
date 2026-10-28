/**
 * var/ 演示数据清理(默认**预演**,加 `--apply` 才动手)。
 *
 * ★ 为什么需要这个脚本,而不是哪天手工删一遍:
 *   demo / verify 这些入口会打到**真实 var/** 上(verify-gateway 需要一个已经
 *   在跑的网关),所以跑一轮测试就会往会话记录、台账、审计目录里灌一批
 *   `FLOW-xxxx`、`gw-xxxx` 这类没有任何业务意义的残留。
 *   一年下来没人记得"哪些能删、哪些是演示数据",于是要么不敢清、要么清错。
 *   把判据写进代码,清理就变成可复现、可复核的一件事。
 *
 * ★ 三条纪律:
 *   ① **只归档,不删除**:全部移动到 `var/_archive/cleanup-<时间戳>/`,
 *      原文件整份留档 —— 清错了可以整份还原(见归档目录里的 MANIFEST.md)。
 *   ② **默认预演**:不带 `--apply` 只打印将要发生什么,不动任何文件。
 *   ③ **有写入者就不动手**:`var/audit/.writer.lock` 还在,说明可能有网关在跑;
 *      而网关把会话/台账缓存在内存里,清理结果会被它下一次落盘覆盖回去 ——
 *      所以此时拒绝执行(除非明确 `--force`,或 `--drop-lock` 表示已确认没有写入者)。
 *
 * 用法:
 *   node tools/cleanup-var.mjs                             # 预演
 *   node tools/cleanup-var.mjs --apply                     # 执行归档
 *   node tools/cleanup-var.mjs --apply --drop-lock          # 同时删掉陈旧的审计写锁
 *   node tools/cleanup-var.mjs --apply --drop-lock --flow-usage=6,3   # 同时把常用流程次数改成 6/3
 *
 * ★ `--drop-lock` 只应由人来下:Windows 上 pid 被判活的判据会误判
 *   (见 packages/core/src/audit/hashChain.ts 的注释),脚本自己不敢替你决定
 *   "那把锁的主人是死是活"。下这个参数之前,先确认没有任何网关在跑。
 */
import { copyFile, mkdir, readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

// ============================================================================
// 清理判据(改这里就是改口径;每条都请写清"为什么")
// ============================================================================

/**
 * 测试残留的会话 ID。
 *
 * 这些前缀是各验证脚本 `sid()` 生成的:`FLOW-`/`CITE-`/`SUG-`/`APPROVE-`/
 * `BLOCK-`/`CONFIRM-`/`DOC-`/`REVIEW-`/`SPECIALIST-` 来自 verify-extras 与
 * verify-gateway,`gw-`/`gw2-`… 来自网关验证,`reuse-` 来自复用流程的用例。
 * 它们**不是客户办过的业务**,留在历史列表里只会淹没真正的记录。
 *
 * ★ 用前缀白名单而不是"猜哪个像测试":猜错方向反了 —— 漏掉只是多留几行,
 *   而误判会把客户的真实记录当垃圾归档。所以只认已知的测试前缀。
 */
const TEST_SESSION_RE = /^(FLOW|CITE|SUG|APPROVE|BLOCK|CONFIRM|DOC|REVIEW|SPECIALIST|reuse)-|^gw\d?-/;

/**
 * 没有业务的空会话。
 *
 * 标题是「新会话」意味着**一个能力都没跑成**(真正的业务会把标题写成
 * 「转账汇款 · 王秀兰」这种)。这类会话在历史列表里就是一行看不懂的东西,
 * demo 场景在中途被拦下/转人工时也会留下它。
 *
 * ★ 判据必须同时满足"没标题"与"台账 0 行":万一将来有会话因为别的原因
 *   暂时没写标题,只要它办过业务,我们就不会动它。
 */
const EMPTY_SESSION_TITLE = "新会话";

/** 审计分片(测试进程并发写时产生的独立小链)。主链 audit-chain.jsonl 永不在此列 */
const AUDIT_SHARD_RE = /^audit-chain\.\d+\..+\.jsonl$/;

/** 与业务无关的临时日志 */
const LOG_RE = /\.log$/;

// ============================================================================

const args = new Set(process.argv.slice(2));
const APPLY = args.has("--apply");
const DROP_LOCK = args.has("--drop-lock");
const FORCE = args.has("--force");
const flowUsageArg = process.argv.find((a) => a.startsWith("--flow-usage="));
const FLOW_USAGE = flowUsageArg
  ? flowUsageArg
      .slice("--flow-usage=".length)
      .split(",")
      .map((n) => Number(n.trim()))
      .filter((n) => Number.isFinite(n) && n >= 0)
  : null;

const varDir = resolve(process.cwd(), "var");
if (!existsSync(varDir)) {
  console.error(`找不到 var/ 目录:${varDir}`);
  process.exit(1);
}

const stamp = new Date()
  .toISOString()
  .replace(/[-:T]/g, "")
  .slice(0, 14);
const archiveDir = join(varDir, "_archive", `cleanup-${stamp}`);

const moved = []; // { from, to, why }
const notes = []; // 说明性备注,进 MANIFEST

const rel = (p) => p.slice(process.cwd().length + 1).replace(/\\/g, "/");
const say = (s) => console.log(s);

/** 原子落盘:先写临时文件再改名,避免写一半被杀留下坏 JSON */
async function writeJsonAtomic(path, data) {
  const tmp = `${path}.tmp-${Math.random().toString(36).slice(2, 8)}`;
  await writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
  await rename(tmp, path);
}

async function archiveFile(from, to, why) {
  moved.push({ from, to, why });
  if (!APPLY) return;
  await mkdir(dirname(to), { recursive: true });
  await copyFile(from, to);
}

/**
 * 清单里的"移动列表"。
 *
 * ★ 同类条目必须合并:光审计分片就有 190 个,逐个列出来会把清单撑成两百多行,
 *   而这份清单是给人看的 —— 一屏看不完的清单等于没有清单。
 *   判据是"同一条 why 且落进同一个目录",合并后给出目录与个数。
 */
function renderMoved() {
  const byWhy = new Map();
  for (const m of moved) {
    if (!byWhy.has(m.why)) byWhy.set(m.why, []);
    byWhy.get(m.why).push(m);
  }
  const lines = [];
  for (const [why, entries] of byWhy) {
    if (entries.length > 4) {
      const fromDir = dirname(entries[0].from);
      const toDir = dirname(entries[0].to);
      lines.push(`- \`${rel(fromDir)}/\` 下 **${entries.length} 个文件** → \`${rel(toDir)}/\`(${why})`);
      continue;
    }
    for (const m of entries) lines.push(`- \`${rel(m.from)}\` → \`${rel(m.to)}\`(${why})`);
  }
  return lines;
}

// ---- 0. 写入者守卫 ----
const lockPath = join(varDir, "audit", ".writer.lock");
let lockInfo = null;
if (existsSync(lockPath)) {
  try {
    lockInfo = JSON.parse(await readFile(lockPath, "utf8"));
  } catch {
    lockInfo = { raw: true };
  }
}

say(`\n=== var/ 数据清理${APPLY ? "(执行)" : "(预演,不动任何文件)"} ===`);
say(`var 目录:${varDir}`);
if (lockInfo && !DROP_LOCK && APPLY && !FORCE) {
  console.error(
    `\n✗ 审计写锁还在(${lockPath})\n` +
      `  ${JSON.stringify(lockInfo)}\n` +
      "  这可能意味着有网关在跑 —— 而网关把会话/台账缓存在内存里,\n" +
      "  清理会被它下一次落盘覆盖回去。请先停掉网关,然后:\n" +
      "    · 若确认没有任何写入者:加 --drop-lock 重新执行;\n" +
      "    · 若确实想带着锁清理(知道自己在做什么):加 --force。",
  );
  process.exit(1);
}
if (lockInfo) {
  say(`审计写锁:存在 ${JSON.stringify(lockInfo)}${DROP_LOCK ? " → 将归档并删除" : "(保留)"}`);
}

// ---- 1. 会话记录:挑出测试残留 ----
const sessionsDir = join(varDir, "sessions");
/** 留下来的会话 ID —— 台账裁剪要用它当判据,所以在这里先算出来 */
const keptSessionIds = new Set();

if (existsSync(sessionsDir)) {
  const files = (await readdir(sessionsDir)).filter((f) => f.endsWith(".json"));
  say(`\n--- 会话记录(${files.length} 个客户文件)---`);

  for (const f of files) {
    const path = join(sessionsDir, f);
    const file = JSON.parse(await readFile(path, "utf8"));
    const sessions = Array.isArray(file.sessions) ? file.sessions : [];

    const keep = [];
    for (const s of sessions) {
      if (TEST_SESSION_RE.test(s.sessionId)) continue;
      if (s.title === EMPTY_SESSION_TITLE && (s.operationIds ?? []).length === 0) continue;
      keep.push(s);
    }

    for (const id of keep.map((s) => s.sessionId)) keptSessionIds.add(id);

    const testCount = sessions.filter((s) => TEST_SESSION_RE.test(s.sessionId)).length;
    const emptyCount = sessions.filter(
      (s) => !TEST_SESSION_RE.test(s.sessionId) && s.title === EMPTY_SESSION_TITLE && (s.operationIds ?? []).length === 0,
    ).length;

    say(`  ${f}:${sessions.length} 个会话 → 保留 ${keep.length},归档 ${sessions.length - keep.length}`);
    say(`      其中测试残留 ${testCount} 个,无业务的「${EMPTY_SESSION_TITLE}」${emptyCount} 个`);

    if (keep.length === sessions.length) continue;

    await archiveFile(path, join(archiveDir, "sessions", f), "会话记录原文件(整份留档)");
    if (APPLY) {
      await writeJsonAtomic(path, { ...file, sessions: keep });
      // 自检:写回去的必须还能解析,且条数一致
      const back = JSON.parse(await readFile(path, "utf8"));
      if (back.sessions.length !== keep.length) throw new Error(`${f} 写回后条数不一致`);
    }
  }
}

// ---- 2. 台账:丢掉孤儿行与测试会话的行,保留常用流程与建议冷却 ----
const persDir = join(varDir, "personalization");
if (existsSync(persDir)) {
  const files = (await readdir(persDir)).filter((f) => f.endsWith(".json"));
  say(`\n--- 用户档案与台账(${files.length} 个客户文件)---`);

  for (const f of files) {
    const path = join(persDir, f);
    const file = JSON.parse(await readFile(path, "utf8"));
    const history = Array.isArray(file.history) ? file.history : [];

    const keepRows = history.filter((r) => r.sessionId && keptSessionIds.has(r.sessionId));
    const orphanRows = history.filter((r) => r.sessionId && !keptSessionIds.has(r.sessionId));
    const orphanSessions = new Set(orphanRows.map((r) => r.sessionId));

    say(`  ${f}:台账 ${history.length} 行 → 保留 ${keepRows.length} 行,归档 ${orphanRows.length} 行`);
    say(`      归档行来自 ${orphanSessions.size} 个会话(测试残留 + 已超出 50 会话上限被裁掉的旧会话)`);
    say(`      保留:flows ${(file.flows ?? []).length} 条、建议冷却 ${Object.keys(file.suggestionCooldown ?? {}).length} 键`);

    let flows = file.flows ?? [];
    if (FLOW_USAGE && flows.length > 0) {
      const before = flows.map((x) => x.useCount);
      flows = flows.map((x, i) => (FLOW_USAGE[i] != null ? { ...x, useCount: FLOW_USAGE[i] } : x));
      say(`      ★ 常用流程 useCount:${JSON.stringify(before)} → ${JSON.stringify(flows.map((x) => x.useCount))}`);
      notes.push(`常用流程 useCount 由 ${JSON.stringify(before)} 改为 ${JSON.stringify(flows.map((x) => x.useCount))}(一次性演示口径调整,不是保留策略)`);
    }

    if (keepRows.length === history.length && !FLOW_USAGE) continue;

    await archiveFile(path, join(archiveDir, "personalization", f), "用户档案原文件(整份留档)");
    if (APPLY) {
      await writeJsonAtomic(path, { ...file, flows, history: keepRows });
      const back = JSON.parse(await readFile(path, "utf8"));
      if (back.history.length !== keepRows.length) throw new Error(`${f} 写回去的台账条数不一致`);
    }
  }
}

// ---- 3. 审计:归档测试分片与证据包,主链不动 ----
const auditDir = join(varDir, "audit");
if (existsSync(auditDir)) {
  const files = await readdir(auditDir);
  const shards = files.filter((f) => AUDIT_SHARD_RE.test(f));
  say(`\n--- 审计目录 ---`);
  say(`  主链 audit-chain.jsonl:保留(不动)`);
  say(`  测试分片:归档 ${shards.length} 个`);

  for (const f of shards) {
    await archiveFile(join(auditDir, f), join(archiveDir, "audit-shards", f), "测试进程并发写产生的审计分片");
  }
  if (APPLY) {
    for (const f of shards) await unlink(join(auditDir, f));
  }

  const bundle = join(auditDir, "evidence-bundle.json");
  if (existsSync(bundle)) {
    say(`  证据包 evidence-bundle.json:归档(demo 每次运行都会重新生成)`);
    await archiveFile(bundle, join(archiveDir, "evidence-bundle.json"), "演示运行生成的证据包(可再生)");
    if (APPLY) await unlink(bundle);
  }

  if (lockInfo && DROP_LOCK) {
    await archiveFile(lockPath, join(archiveDir, "audit", ".writer.lock"), "陈旧审计写锁");
    if (APPLY) await unlink(lockPath);
    notes.push("审计写锁已删除。删除前请确认当时没有任何网关在跑 —— 否则可能误删活跃写入者的锁。");
    say(`  ★ 陈旧写锁:归档并删除 → 新审计将重新写入主链`);
  }
}

// ---- 4. 杂项日志 ----
const strayLogs = (await readdir(varDir)).filter((f) => LOG_RE.test(f));
if (strayLogs.length > 0) {
  say(`\n--- 杂项日志 ---`);
  for (const f of strayLogs) {
    say(`  归档 ${f}`);
    await archiveFile(join(varDir, f), join(archiveDir, "logs", f), "历史调试日志");
    if (APPLY) await unlink(join(varDir, f));
  }
}

// ---- 5. 清单 ----
say(`\n=== 汇总 ===`);
say(`  将移动 ${moved.length} 个文件到 ${rel(archiveDir)}/`);
if (!APPLY) {
  say(`\n这是**预演**。确认无误后加 --apply 执行。`);
  process.exit(0);
}

const manifest = [
  `# var/ 清理留档 ${stamp}`,
  "",
  `执行时间:${new Date().toISOString()}`,
  `归档目录:${rel(archiveDir)}/`,
  "",
  "## 判据",
  "",
  `- 测试残留会话:${TEST_SESSION_RE}`,
  `- 无业务会话:标题 = 「${EMPTY_SESSION_TITLE}」且台账 0 行`,
  `- 台账:只保留"所属会话仍在 var/sessions 里"的行(其余是测试残留或已被 50 会话上限裁掉的旧会话)`,
  `- 审计分片:${AUDIT_SHARD_RE}(主链 audit-chain.jsonl 不动)`,
  "",
  "## 移动清单",
  "",
  ...renderMoved(),
  "",
  ...(notes.length > 0 ? ["## 备注", "", ...notes.map((n) => `- ${n}`), ""] : []),
  "## 如何还原",
  "",
  "```powershell",
  "# 整份还原某个文件(例如会话记录)",
  `Copy-Item -Force "${rel(join(archiveDir, "sessions"))}\\*.json" var\\sessions\\`,
  "# 审计分片放回去",
  `Copy-Item -Force "${rel(join(archiveDir, "audit-shards"))}\\*.jsonl" var\\audit\\`,
  "```",
  "",
  "> 还原后请记住:`.writer.lock` 的备份在 `audit/.writer.lock` —— 只在确认没有网关在跑时才需要动它。",
  "",
].join("\n");
await mkdir(archiveDir, { recursive: true });
await writeFile(join(archiveDir, "MANIFEST.md"), manifest, "utf8");

say(`  已写入留档清单:${rel(join(archiveDir, "MANIFEST.md"))}`);
say(`\n完成 ✓(原文件都在归档目录里,可整份还原)`);