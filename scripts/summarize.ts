/**
 * summarize.ts
 * -------------------------------------------------------------------------
 * Lê um "inspection.json" gerado pelo blacklight-collector e imprime um
 * resumo legível dos testes de privacidade, sem precisar abrir o JSON
 * inteiro manualmente.
 *
 * Uso:
 *   npx ts-node scripts/summarize.ts <caminho-para-inspection.json ou pasta>
 *   npx ts-node scripts/summarize.ts demo-dir
 *
 * Ou via package.json:
 *   "summarize": "ts-node scripts/summarize.ts"
 *   npm run summarize -- demo-dir
 *
 * -------------------------------------------------------------------------
 * NOTA SOBRE O SCHEMA:
 * Esta versão foi ajustada a partir de duas inspeções reais geradas pelo
 * seu fork (v3.11.0). O `reports` tem 11 chaves (não 9): além dos 9 testes
 * "clássicos", este fork também gera `tiktok_pixel_events` e
 * `twitter_pixel_events`.
 *
 * `key_logging` veio vazio (`{}`) nas duas amostras usadas para calibrar
 * este script, então o formatador dele ainda é genérico — assim que você
 * rodar uma inspeção onde ele detecte algo, me envie o inspection.json (ou
 * só esse trecho) e eu ajusto o formatador específico.
 * -------------------------------------------------------------------------
 */

import * as fs from "fs";
import * as path from "path";
import { URL } from "url";

// ---------------------------------------------------------------------------
// Cores simples via ANSI (sem dependências externas)
// ---------------------------------------------------------------------------
const color = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
};

function paint(text: string, c: keyof typeof color): string {
  return `${color[c]}${text}${color.reset}`;
}

function ok(msg: string): string {
  return paint(`  ✓ ${msg}`, "green");
}

function warn(msg: string): string {
  return paint(`  ⚠ ${msg}`, "yellow");
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

// ---------------------------------------------------------------------------
// Metadados amigáveis para cada teste conhecido, na ordem de exibição
// ---------------------------------------------------------------------------
interface TestMeta {
  label: string;
  description: string;
}

const TEST_METADATA: Record<string, TestMeta> = {
  behaviour_event_listeners: {
    label: "Escuta de eventos de comportamento",
    description:
      "Scripts que registram listeners de teclado/mouse/toque para observar a interação do usuário.",
  },
  canvas_fingerprinters: {
    label: "Fingerprinting via Canvas",
    description:
      "Scripts que desenham no <canvas> e leem o resultado para gerar um identificador único do navegador.",
  },
  canvas_font_fingerprinters: {
    label: "Fingerprinting de fontes via Canvas",
    description:
      "Scripts que medem a renderização de fontes via canvas para identificar o dispositivo.",
  },
  cookies: {
    label: "Cookies",
    description: "Cookies definidos durante a inspeção, de primeira e terceira parte.",
  },
  fb_pixel_events: {
    label: "Facebook Pixel",
    description: "Requisições enviadas ao Facebook/Meta Pixel.",
  },
  tiktok_pixel_events: {
    label: "TikTok Pixel",
    description: "Requisições enviadas ao TikTok Pixel.",
  },
  twitter_pixel_events: {
    label: "Twitter/X Pixel",
    description: "Requisições enviadas ao pixel de rastreamento do X (Twitter).",
  },
  google_analytics_events: {
    label: "Google Analytics",
    description: "Eventos enviados ao Google Analytics / Google Tag Manager.",
  },
  key_logging: {
    label: "Key Logging (captura de digitação)",
    description: "Campos de formulário capturados enquanto o usuário digita, antes do envio.",
  },
  session_recorders: {
    label: "Gravação de sessão",
    description: "Serviços de session replay (ex: Hotjar) que gravam a sessão do usuário.",
  },
  third_party_trackers: {
    label: "Rastreadores de terceiros",
    description: "Requisições de rede para domínios de terceiros classificados como rastreadores.",
  },
};

// Ordem de exibição: os 9 "clássicos" primeiro, na ordem pedida, depois os extras
const TEST_ORDER = [
  "behaviour_event_listeners",
  "canvas_fingerprinters",
  "canvas_font_fingerprinters",
  "cookies",
  "fb_pixel_events",
  "google_analytics_events",
  "key_logging",
  "session_recorders",
  "third_party_trackers",
  "tiktok_pixel_events",
  "twitter_pixel_events",
];

// ---------------------------------------------------------------------------
// Tipos observados nas amostras reais
// ---------------------------------------------------------------------------
interface CookieEntry {
  name: string;
  domain: string;
  third_party?: boolean;
  session?: boolean;
  secure?: boolean;
  httpOnly?: boolean;
  expires?: string | number;
}

interface TrackingRequestEntry {
  type?: string;
  url?: string;
  raw?: string; // google_analytics_events usa "raw" em vez de "url"
  data?: {
    listName?: string;
    filter?: string;
    query?: Record<string, unknown>;
  };
}

// ---------------------------------------------------------------------------
// Formatador: cookies
// ---------------------------------------------------------------------------
function formatCookies(list: CookieEntry[]): string {
  if (list.length === 0) return ok("Nenhum cookie definido.");

  const thirdParty = list.filter((c) => c.third_party);
  const firstParty = list.filter((c) => !c.third_party);
  const persistent = list.filter((c) => c.session === false);

  const lines: string[] = [];
  lines.push(
    warn(
      `${list.length} cookie(s) — ${firstParty.length} de 1ª parte, ${thirdParty.length} de 3ª parte, ${persistent.length} persistente(s)`
    )
  );

  // Prioriza mostrar os de terceira parte primeiro (mais relevantes p/ privacidade)
  const toShow = [...thirdParty, ...firstParty];
  toShow.forEach((c) => {
    const tag = c.third_party ? paint("[3ª parte]", "yellow") : paint("[1ª parte]", "dim");
    const persist = c.session === false ? "persistente" : "sessão";
    lines.push(`    - ${tag} ${c.name} (${c.domain}, ${persist})`);
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Formatador: listas de "TrackingRequest" (trackers, GA, FB/TikTok/Twitter pixel)
// ---------------------------------------------------------------------------
function formatTrackingRequests(list: TrackingRequestEntry[]): string {
  if (list.length === 0) return ok("Nenhuma requisição detectada.");

  // Agrupa por host de destino, contando ocorrências
  const byHost = new Map<string, { count: number; listNames: Set<string> }>();
  list.forEach((item) => {
    const url = item.url ?? item.raw ?? "";
    const host = hostOf(url);
    const entry = byHost.get(host) ?? { count: 0, listNames: new Set<string>() };
    entry.count += 1;
    if (item.data?.listName) entry.listNames.add(item.data.listName);
    byHost.set(host, entry);
  });

  const sortedHosts = [...byHost.entries()].sort((a, b) => b[1].count - a[1].count);

  const lines: string[] = [];
  lines.push(warn(`${list.length} requisição(ões) para ${byHost.size} domínio(s) distinto(s):`));
  sortedHosts.forEach(([host, info]) => {
    const listNames = info.listNames.size > 0 ? ` (via ${[...info.listNames].join(", ")})` : "";
    lines.push(`    - ${host}: ${info.count}x${listNames}`);
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Formatador: behaviour_event_listeners
// dict: categoria (KEYBOARD/MOUSE/...) -> script -> [eventos]
// ---------------------------------------------------------------------------
function formatBehaviourEventListeners(data: Record<string, Record<string, string[]>>): string {
  const categories = Object.keys(data);
  if (categories.length === 0) return ok("Nenhum listener de comportamento detectado.");

  const lines: string[] = [];
  categories.forEach((cat) => {
    const scripts = data[cat];
    const scriptEntries = Object.entries(scripts);
    lines.push(warn(`${cat}: ${scriptEntries.length} script(s) distinto(s)`));
    scriptEntries.forEach(([script, events]) => {
      const host = script.startsWith("http") ? hostOf(script) : script;
      lines.push(`      - ${host}: [${events.join(", ")}]`);
    });
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Formatador: canvas_fingerprinters
// dict fixo: data_url, fingerprinters, styles, texts
// ---------------------------------------------------------------------------
function formatCanvasFingerprinters(data: Record<string, unknown>): string {
  const subkeys = ["data_url", "fingerprinters", "styles", "texts"];
  const active = subkeys.filter((k) => {
    const v = data[k];
    if (Array.isArray(v)) return v.length > 0;
    if (v && typeof v === "object") return Object.keys(v).length > 0;
    return Boolean(v);
  });

  if (active.length === 0) return ok("Nenhum fingerprinting via canvas detectado.");

  const lines: string[] = [warn(`Atividade em: ${active.join(", ")}`)];
  active.forEach((k) => {
    const v = data[k];
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const entries = Object.entries(v as Record<string, unknown>);
      lines.push(`    - ${k}: ${entries.length} script(s)`);
      entries.forEach(([script, val]) => {
        const host = script.startsWith("http") ? hostOf(script) : script;
        const valStr = Array.isArray(val) ? val.join(", ") : JSON.stringify(val);
        lines.push(`        • ${host}: ${valStr}`);
      });
    } else if (Array.isArray(v)) {
      lines.push(`    - ${k}: ${v.length} item(ns)`);
      v.forEach((item) => {
        lines.push(`        • ${typeof item === "object" ? JSON.stringify(item) : String(item)}`);
      });
    }
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Formatador: canvas_font_fingerprinters
// dict fixo: canvas_font, text_measure
// ---------------------------------------------------------------------------
function formatCanvasFontFingerprinters(data: Record<string, unknown>): string {
  const subkeys = ["canvas_font", "text_measure"];
  const active = subkeys.filter((k) => {
    const v = data[k];
    return v && typeof v === "object" && Object.keys(v as object).length > 0;
  });

  if (active.length === 0) return ok("Nenhum fingerprinting de fontes detectado.");

  const lines: string[] = [warn(`Atividade em: ${active.join(", ")}`)];
  active.forEach((k) => {
    const scripts = Object.keys(data[k] as Record<string, unknown>);
    lines.push(`    - ${k}: ${scripts.length} script(s)`);
    scripts.forEach((script) => {
      lines.push(`        • ${hostOf(script)}`);
    });
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Formatador: session_recorders
// dict: domínio -> [scripts]
// ---------------------------------------------------------------------------
function formatSessionRecorders(data: Record<string, string[]>): string {
  const domains = Object.keys(data);
  if (domains.length === 0) return ok("Nenhum serviço de gravação de sessão detectado.");

  const lines: string[] = [warn(`${domains.length} serviço(s) de gravação de sessão detectado(s):`)];
  domains.forEach((domain) => {
    lines.push(`    - ${domain} (${data[domain].length} script(s))`);
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Fallback genérico — usado para key_logging (schema ainda não confirmado
// com um caso positivo) e qualquer chave nova/desconhecida
// ---------------------------------------------------------------------------
function formatGeneric(value: unknown): string {
  if (value === undefined) return paint("  (não presente neste relatório)", "dim");
  if (value === null) return ok("Nenhum achado.");

  if (typeof value === "boolean") return value ? warn("Detectado (true)") : ok("Não detectado (false)");
  if (typeof value === "number") return value > 0 ? warn(`${value} ocorrência(s)`) : ok("0 ocorrências");

  if (Array.isArray(value)) {
    if (value.length === 0) return ok("Nenhum achado (array vazio).");
    const lines = [warn(`${value.length} achado(s):`)];
    value.forEach((item) => {
      lines.push(`    - ${typeof item === "object" ? JSON.stringify(item) : String(item)}`);
    });
    return lines.join("\n");
  }

  if (typeof value === "object") {
    const keys = Object.keys(value as object);
    if (keys.length === 0) return ok("Nenhum achado (objeto vazio).");
    const lines = [warn(`Objeto com ${keys.length} chave(s):`)];
    keys.forEach((k) => {
      const v = (value as Record<string, unknown>)[k];
      lines.push(`    - ${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
    });
    return lines.join("\n");
  }

  return `  ${String(value)}`;
}

// ---------------------------------------------------------------------------
// Roteador: escolhe o formatador certo para cada chave conhecida
// ---------------------------------------------------------------------------
function formatReport(key: string, value: unknown): string {
  switch (key) {
    case "cookies":
      return formatCookies((value as CookieEntry[]) ?? []);
    case "third_party_trackers":
    case "google_analytics_events":
    case "fb_pixel_events":
    case "tiktok_pixel_events":
    case "twitter_pixel_events":
      return formatTrackingRequests((value as TrackingRequestEntry[]) ?? []);
    case "behaviour_event_listeners":
      return formatBehaviourEventListeners(
        (value as Record<string, Record<string, string[]>>) ?? {}
      );
    case "canvas_fingerprinters":
      return formatCanvasFingerprinters((value as Record<string, unknown>) ?? {});
    case "canvas_font_fingerprinters":
      return formatCanvasFontFingerprinters((value as Record<string, unknown>) ?? {});
    case "session_recorders":
      return formatSessionRecorders((value as Record<string, string[]>) ?? {});
    case "key_logging":
    default:
      return formatGeneric(value);
  }
}

// ---------------------------------------------------------------------------
// Remove códigos de cor ANSI (\x1b[...m) — necessário para o arquivo .txt,
// que não deve conter caracteres de controle de terminal.
// ---------------------------------------------------------------------------
function stripAnsi(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;]*m/g, "");
}

// ---------------------------------------------------------------------------
// CSV — formato "long": uma linha por achado, pensado para filtrar/dinamizar
// em planilha (Excel/Google Sheets/LibreOffice Calc).
// Colunas fixas: site, test, test_label, category, target, detail, count
// ---------------------------------------------------------------------------
interface CsvRow {
  site: string;
  test: string;
  test_label: string;
  category: string;
  target: string;
  detail: string;
  count: string;
}

const CSV_COLUMNS: (keyof CsvRow)[] = ["site", "test", "test_label", "category", "target", "detail", "count"];

function csvEscape(value: string): string {
  if (/[",\n;]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function rowsToCsv(rows: CsvRow[]): string {
  const header = CSV_COLUMNS.join(",");
  const lines = rows.map((row) => CSV_COLUMNS.map((col) => csvEscape(row[col])).join(","));
  return [header, ...lines].join("\n") + "\n";
}

// ---- Extratores: um por formato de teste, devolvendo linhas de CSV --------

function cookiesToRows(site: string, list: CookieEntry[]): CsvRow[] {
  const meta = TEST_METADATA.cookies;
  return list.map((c) => ({
    site,
    test: "cookies",
    test_label: meta.label,
    category: c.third_party ? "third_party" : "first_party",
    target: c.domain ?? "",
    detail: `${c.name ?? ""} (${c.session === false ? "persistente" : "sessão"}${c.secure ? ", secure" : ""}${
      c.httpOnly ? ", httpOnly" : ""
    })`,
    count: "1",
  }));
}

function trackingRequestsToRows(testKey: string, list: TrackingRequestEntry[]): CsvRow[] {
  const meta = TEST_METADATA[testKey] ?? { label: testKey, description: "" };
  return list.map((item) => {
    const url = item.url ?? item.raw ?? "";
    return {
      site: "",
      test: testKey,
      test_label: meta.label,
      category: item.data?.listName ?? "",
      target: hostOf(url),
      detail: url,
      count: "1",
    };
  });
}

function behaviourEventListenersToRows(data: Record<string, Record<string, string[]>>): CsvRow[] {
  const meta = TEST_METADATA.behaviour_event_listeners;
  const rows: CsvRow[] = [];
  Object.entries(data).forEach(([category, scripts]) => {
    Object.entries(scripts).forEach(([script, events]) => {
      rows.push({
        site: "",
        test: "behaviour_event_listeners",
        test_label: meta.label,
        category,
        target: script.startsWith("http") ? hostOf(script) : script,
        detail: events.join("|"),
        count: String(events.length),
      });
    });
  });
  return rows;
}

function canvasFingerprintersToRows(data: Record<string, unknown>): CsvRow[] {
  const meta = TEST_METADATA.canvas_fingerprinters;
  const rows: CsvRow[] = [];
  ["data_url", "fingerprinters", "styles", "texts"].forEach((subkey) => {
    const v = data[subkey];
    if (v && typeof v === "object" && !Array.isArray(v)) {
      Object.entries(v as Record<string, unknown>).forEach(([script, val]) => {
        rows.push({
          site: "",
          test: "canvas_fingerprinters",
          test_label: meta.label,
          category: subkey,
          target: script.startsWith("http") ? hostOf(script) : script,
          detail: Array.isArray(val) ? val.join("|") : JSON.stringify(val),
          count: "",
        });
      });
    } else if (Array.isArray(v)) {
      v.forEach((item) => {
        rows.push({
          site: "",
          test: "canvas_fingerprinters",
          test_label: meta.label,
          category: subkey,
          target: "",
          detail: typeof item === "object" ? JSON.stringify(item) : String(item),
          count: "",
        });
      });
    }
  });
  return rows;
}

function canvasFontFingerprintersToRows(data: Record<string, unknown>): CsvRow[] {
  const meta = TEST_METADATA.canvas_font_fingerprinters;
  const rows: CsvRow[] = [];
  ["canvas_font", "text_measure"].forEach((subkey) => {
    const v = data[subkey];
    if (v && typeof v === "object") {
      Object.keys(v as Record<string, unknown>).forEach((script) => {
        rows.push({
          site: "",
          test: "canvas_font_fingerprinters",
          test_label: meta.label,
          category: subkey,
          target: script.startsWith("http") ? hostOf(script) : script,
          detail: "",
          count: "",
        });
      });
    }
  });
  return rows;
}

function sessionRecordersToRows(data: Record<string, string[]>): CsvRow[] {
  const meta = TEST_METADATA.session_recorders;
  return Object.entries(data).map(([domain, scripts]) => ({
    site: "",
    test: "session_recorders",
    test_label: meta.label,
    category: "",
    target: domain,
    detail: scripts.join("|"),
    count: String(scripts.length),
  }));
}

function genericToRows(testKey: string, value: unknown): CsvRow[] {
  const meta = TEST_METADATA[testKey] ?? { label: testKey, description: "" };
  const rows: CsvRow[] = [];

  if (value === undefined || value === null) return rows;

  if (Array.isArray(value)) {
    value.forEach((item) => {
      rows.push({
        site: "",
        test: testKey,
        test_label: meta.label,
        category: "",
        target: "",
        detail: typeof item === "object" ? JSON.stringify(item) : String(item),
        count: "",
      });
    });
    return rows;
  }

  if (typeof value === "object") {
    Object.entries(value as Record<string, unknown>).forEach(([k, v]) => {
      rows.push({
        site: "",
        test: testKey,
        test_label: meta.label,
        category: k,
        target: "",
        detail: typeof v === "object" ? JSON.stringify(v) : String(v),
        count: "",
      });
    });
    return rows;
  }

  // booleano/número/string simples
  rows.push({
    site: "",
    test: testKey,
    test_label: meta.label,
    category: "",
    target: "",
    detail: String(value),
    count: "",
  });
  return rows;
}

// ---- Roteador: monta todas as linhas de CSV para um inspection.json -------
function buildCsvRows(reports: Record<string, unknown>, site: string): CsvRow[] {
  const allKeys = [...TEST_ORDER.filter((k) => k in reports), ...Object.keys(reports).filter((k) => !TEST_ORDER.includes(k))];
  let rows: CsvRow[] = [];

  allKeys.forEach((testKey) => {
    const value = reports[testKey];
    let testRows: CsvRow[];
    switch (testKey) {
      case "cookies":
        testRows = cookiesToRows(site, (value as CookieEntry[]) ?? []);
        break;
      case "third_party_trackers":
      case "google_analytics_events":
      case "fb_pixel_events":
      case "tiktok_pixel_events":
      case "twitter_pixel_events":
        testRows = trackingRequestsToRows(testKey, (value as TrackingRequestEntry[]) ?? []);
        break;
      case "behaviour_event_listeners":
        testRows = behaviourEventListenersToRows((value as Record<string, Record<string, string[]>>) ?? {});
        break;
      case "canvas_fingerprinters":
        testRows = canvasFingerprintersToRows((value as Record<string, unknown>) ?? {});
        break;
      case "canvas_font_fingerprinters":
        testRows = canvasFontFingerprintersToRows((value as Record<string, unknown>) ?? {});
        break;
      case "session_recorders":
        testRows = sessionRecordersToRows((value as Record<string, string[]>) ?? {});
        break;
      default:
        testRows = genericToRows(testKey, value);
    }
    // preenche a coluna "site" (definida só em cookiesToRows por conveniência)
    testRows.forEach((r) => (r.site = site));
    rows = rows.concat(testRows);
  });

  return rows;
}

// ---------------------------------------------------------------------------
// Monta um nome de arquivo padrão para o relatório, caso o usuário não
// informe um caminho de saída explícito.
// Ex: resumo-wayground.com-2026-08-13T18-40-00.txt
// ---------------------------------------------------------------------------
function defaultOutputPath(jsonDir: string, host: string, ext: string): string {
  const safeHost = String(host || "site").replace(/[^a-z0-9.-]/gi, "_");
  const ts = new Date().toISOString().replace(/:/g, "-").split(".")[0];
  return path.join(jsonDir, `resumo-${safeHost}-${ts}.${ext}`);
}

// ---------------------------------------------------------------------------
// Programa principal
// ---------------------------------------------------------------------------
function main() {
  const args = process.argv.slice(2);
  const inputArg = args[0];

  const getFlag = (name: string): string | undefined => {
    const match = args.find((a) => a.startsWith(`--${name}=`));
    return match ? match.slice(`--${name}=`.length) : undefined;
  };

  const noFile = args.includes("--no-file");
  const noTxt = args.includes("--no-txt") || noFile;
  const noCsv = args.includes("--no-csv") || noFile;
  const explicitTxtPath = getFlag("out");
  const explicitCsvPath = getFlag("csv");

  if (!inputArg) {
    console.error(
      paint(
        "Uso: ts-node scripts/summarize.ts <inspection.json ou pasta> [--out=relatorio.txt] [--csv=relatorio.csv] [--no-txt] [--no-csv] [--no-file]",
        "red"
      )
    );
    process.exit(1);
  }

  let jsonPath = inputArg;
  const stat = fs.statSync(jsonPath);
  if (stat.isDirectory()) {
    jsonPath = path.join(jsonPath, "inspection.json");
  }

  if (!fs.existsSync(jsonPath)) {
    console.error(paint(`Arquivo não encontrado: ${jsonPath}`, "red"));
    process.exit(1);
  }

  const raw = fs.readFileSync(jsonPath, "utf-8");
  let inspection: Record<string, unknown> = {};
  try {
    inspection = JSON.parse(raw);
  } catch (err) {
    console.error(paint(`Erro ao parsear JSON: ${(err as Error).message}`, "red"));
    process.exit(1);
  }

  // Buffer com todas as linhas impressas — usado depois para gravar o .txt
  const outputLines: string[] = [];
  function print(line = "") {
    console.log(line);
    outputLines.push(line);
  }

  print(paint("=".repeat(72), "cyan"));
  print(paint("  RESUMO DA INSPEÇÃO BLACKLIGHT", "bold"));
  print(paint("=".repeat(72), "cyan"));
  print(`Site inspecionado : ${inspection.host ?? inspection.uri_ins ?? "?"}`);
  print(`URL final          : ${inspection.uri_dest ?? "?"}`);
  print(`Início             : ${inspection.start_time ?? "?"}`);
  print(`Fim                : ${inspection.end_time ?? "?"}`);

  const hosts = inspection.hosts as { requests?: { first_party?: string[]; third_party?: string[] } } | undefined;
  if (hosts?.requests) {
    print(
      `Domínios            : ${hosts.requests.first_party?.length ?? 0} 1ª parte, ${
        hosts.requests.third_party?.length ?? 0
      } 3ª parte`
    );
  }
  print("");

  const reports = (inspection.reports ?? {}) as Record<string, unknown>;
  const site = String(inspection.host ?? inspection.uri_ins ?? "site");

  if (Object.keys(reports).length === 0) {
    print(paint("Aviso: não encontrei a chave 'reports' no JSON informado, ou ela está vazia.", "red"));
  }

  TEST_ORDER.forEach((testKey) => {
    if (!(testKey in reports)) return; // pula testes que não existem nesta versão
    const meta = TEST_METADATA[testKey];
    print(paint("-".repeat(72), "blue"));
    print(`${paint(meta.label, "bold")}  ${paint(`[${testKey}]`, "dim")}`);
    print(paint(meta.description, "dim"));
    print(formatReport(testKey, reports[testKey]));
    print("");
  });

  const extraKeys = Object.keys(reports).filter((k) => !TEST_ORDER.includes(k));
  if (extraKeys.length > 0) {
    print(paint("-".repeat(72), "blue"));
    print(paint("Chaves novas em 'reports' (ainda não mapeadas neste script):", "bold"));
    extraKeys.forEach((k) => {
      print(`${paint(k, "cyan")}:`);
      print(formatGeneric(reports[k]));
      print("");
    });
  }

  print(paint("=".repeat(72), "cyan"));

  const jsonDir = path.dirname(jsonPath);

  // ---- Gera o arquivo .txt ------------------------------------------------
  if (!noTxt) {
    const outPath = explicitTxtPath ?? defaultOutputPath(jsonDir, site, "txt");
    const plainText = outputLines.map(stripAnsi).join("\n") + "\n";
    fs.writeFileSync(outPath, plainText, "utf-8");
    console.log(paint(`\nRelatório (.txt) salvo em: ${outPath}`, "green"));
  }

  // ---- Gera o arquivo .csv (uma linha por achado, para planilha) ----------
  if (!noCsv) {
    const csvPath = explicitCsvPath ?? defaultOutputPath(jsonDir, site, "csv");
    const rows = buildCsvRows(reports, site);
    fs.writeFileSync(csvPath, rowsToCsv(rows), "utf-8");
    console.log(paint(`Relatório (.csv) salvo em: ${csvPath} (${rows.length} linha(s))`, "green"));
  }
}

main();