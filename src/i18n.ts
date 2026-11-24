import { AsyncLocalStorage } from 'node:async_hooks';
import { tr } from './locales/tr';

/**
 * Languages (DESIGN §4.31). Pages and emails are written in English; for another language the
 * finished HTML (or email text) is translated from that language's catalog, one sentence at a
 * time. A sentence the catalog lacks stays English, so a page is never broken by a missing
 * translation, and `test/i18n.test.ts` lists what is missing.
 *
 * Adding a language: add its code to LOCALES and LOCALE_NAMES, write src/locales/<code>.ts
 * (a copy of tr.ts translated), and register it in CATALOGS.
 */

export const LOCALES = ['en', 'tr'] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = 'en';

/** Each language in its own name, for the language switcher. */
export const LOCALE_NAMES: Record<Locale, string> = { en: 'English', tr: 'Türkçe' };

/** The cookie that remembers a chosen language (strictly necessary: it is the user's choice). */
export const LOCALE_COOKIE = '__Host-lang';
export const LOCALE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60;

export interface Catalog {
  /**
   * English sentence → translation. Inline elements are numbered markers: `<0>`…`</0>` for an
   * element with content, `<0/>` for one kept whole (code, svg). `{0}`, `{1}` match any text
   * (names, numbers) and are put back where the translation has them.
   */
  messages: Record<string, string>;
  /** January … December. */
  months: readonly string[];
  /** Jan … Dec. */
  monthsShort: readonly string[];
}

const CATALOGS: Partial<Record<Locale, Catalog>> = { tr };

export function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && (LOCALES as readonly string[]).includes(value);
}

/** The best supported language from an Accept-Language header or a ui_locales list. */
export function fromPreferences(header: string | null | undefined): Locale | null {
  if (!header) return null;
  const ranked = header
    .split(/[,\s]+/)
    .map((part, index) => {
      const [tag = '', ...params] = part.split(';');
      const q = params.map((p) => /^q=([0-9.]+)$/.exec(p.trim())?.[1]).find(Boolean);
      return { tag: tag.trim().toLowerCase(), q: q === undefined ? 1 : Number(q), index };
    })
    .filter((p) => p.tag && p.q > 0)
    .sort((a, b) => b.q - a.q || a.index - b.index);
  for (const { tag } of ranked) {
    const base = tag.split('-')[0];
    if (isLocale(base)) return base;
  }
  return null;
}

/**
 * The request's language: an explicit choice (`?lang=`, OpenID Connect's `ui_locales`), then the
 * remembered choice (cookie), then the account's saved language, then the browser's.
 */
export function pickLocale(input: {
  query?: string | null | undefined;
  uiLocales?: string | null | undefined;
  cookie?: string | null | undefined;
  account?: string | null | undefined;
  acceptLanguage?: string | null | undefined;
}): Locale {
  if (isLocale(input.query)) return input.query;
  const ui = fromPreferences(input.uiLocales);
  if (ui) return ui;
  if (isLocale(input.cookie)) return input.cookie;
  if (isLocale(input.account)) return input.account;
  return fromPreferences(input.acceptLanguage) ?? DEFAULT_LOCALE;
}

// ---- The request's language -----------------------------------------------------------------

interface LocaleContext {
  locale: Locale;
  /** The page's address, for the language switcher. */
  url: URL;
}

const store = new AsyncLocalStorage<LocaleContext>();

export function withLocale<T>(context: LocaleContext, run: () => Promise<T>): Promise<T> {
  return store.run(context, run);
}

/** The language of the request being handled (English outside one). */
export function currentLocale(): Locale {
  return store.getStore()?.locale ?? DEFAULT_LOCALE;
}

/** Links to this page in every language; the current one is marked. Never translated. */
export function languageSwitcher(): string {
  const context = store.getStore();
  const locale = context?.locale ?? DEFAULT_LOCALE;
  const links = LOCALES.map((code) => {
    let href = `?lang=${code}`;
    if (context) {
      const url = new URL(context.url);
      url.searchParams.set('lang', code);
      href = url.pathname + url.search;
    }
    const attrs = code === locale ? ' aria-current="true"' : ` hreflang="${code}"`;
    return `<a href="${href.replace(/&/g, '&amp;')}" lang="${code}" translate="no"${attrs}>${LOCALE_NAMES[code]}</a>`;
  });
  return `<nav class="languages" aria-label="Language">${links.join('')}</nav>`;
}

// ---- Translating ----------------------------------------------------------------------------

interface Compiled {
  exact: Map<string, string>;
  patterns: { regex: RegExp; translation: string }[];
  months: [RegExp, (m: string) => string];
}

const compiled = new Map<Locale, Compiled>();
let missing: Set<string> | null = null;

/** Records sentences without a translation (tests). */
export function collectMissing(): Set<string> {
  missing = new Set();
  return missing;
}

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const EN_MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

function compile(locale: Locale): Compiled | null {
  const catalog = CATALOGS[locale];
  if (!catalog) return null;
  const done = compiled.get(locale);
  if (done) return done;
  const exact = new Map<string, string>();
  const patterns: Compiled['patterns'] = [];
  for (const [english, translation] of Object.entries(catalog.messages)) {
    if (/\{\d+\}/.test(english)) {
      const source = escapeRegex(english).replace(/\\\{(\d+)\\\}/g, '(?<p$1>.+?)');
      patterns.push({ regex: new RegExp(`^${source}$`, 's'), translation });
    } else {
      exact.set(english, translation);
    }
  }
  // The most specific patterns (most literal text) first.
  patterns.sort(
    (a, b) =>
      b.regex.source.replace(/\(\?<p\d+>\.\+\?\)/g, '').length -
      a.regex.source.replace(/\(\?<p\d+>\.\+\?\)/g, '').length,
  );
  const full = EN_MONTHS.join('|');
  const short = EN_MONTHS.map((m) => m.slice(0, 3)).join('|');
  const monthRegex = new RegExp(`\\b(\\d{1,2}) (${full}|${short})\\b(?= \\d{4})`, 'g');
  const result: Compiled = {
    exact,
    patterns,
    months: [
      monthRegex,
      (match: string) =>
        match.replace(/(\d{1,2}) (\w+)/, (_, day: string, month: string) => {
          const i = EN_MONTHS.indexOf(month);
          const name =
            i >= 0
              ? catalog.months[i]
              : catalog.monthsShort[EN_MONTHS.findIndex((m) => m.startsWith(month))];
          return `${day} ${name ?? month}`;
        }),
    ],
  };
  compiled.set(locale, result);
  return result;
}

/** One sentence (markers and normalised spaces) in the language, or null. */
function lookup(c: Compiled, key: string): string | null {
  const hit = c.exact.get(key);
  if (hit !== undefined) return hit;
  for (const { regex, translation } of c.patterns) {
    const m = regex.exec(key);
    if (!m) continue;
    // A captured part may itself be a sentence of the catalog ("with {0}" → "Google and email").
    return translation.replace(/\{(\d+)\}/g, (_, n: string) => {
      const value = m.groups?.[`p${n}`] ?? '';
      return (value && c.exact.get(value)) ?? value;
    });
  }
  // Lists joined with " · " (meta lines): each part on its own.
  if (key.includes(' · ')) {
    const parts = key.split(' · ');
    const translated = parts.map((part) => lookup(c, part));
    if (translated.some((t) => t !== null)) {
      return parts.map((part, i) => translated[i] ?? (keep(part) ? part : miss(part))).join(' · ');
    }
  }
  return null;
}

/** Text that needs no translation: numbers, addresses, names of things, symbols. */
function keep(key: string): boolean {
  return (
    !/[A-Za-z]{2}/.test(key.replace(/<\/?\d+\/?>/g, '')) ||
    // Dates and times (their month names are translated anyway), domains, event names.
    /^\d{1,2} [A-Z][a-z]{2,8} \d{4}(, \d{2}:\d{2}( UTC)?)?$/.test(key) ||
    /^[a-z0-9-]+(\.[a-z0-9_-]+)+$/.test(key) ||
    /^[\w.+-]+@[\w.-]+$/.test(key) ||
    /^(https?:\/\/|\/)\S*$/.test(key) ||
    /^(2earl|Google|SAML|SAML 2\.0|OpenID Connect|SCIM|MCP|OIDC|Okta|Microsoft Entra ID|JSON|CSV|API|<\d\/> \(HTTP-POST\)|<\d\/> TXT <\d\/>)$/.test(
      key,
    )
  );
}

function miss(key: string): string {
  missing?.add(key);
  return key;
}

/** A plain-text sentence (emails, JSON messages) in the language. */
export function translate(text: string, locale: Locale): string {
  const c = locale === DEFAULT_LOCALE ? null : compile(locale);
  if (!c) return text;
  const key = text.replace(/\s+/g, ' ').trim();
  if (!key) return text;
  const lead = /^\s*/.exec(text)?.[0] ?? '';
  const trail = /\s*$/.exec(text)?.[0] ?? '';
  const found = lookup(c, key);
  const out = found ?? (keep(key) ? key : miss(key));
  return lead + out.replace(c.months[0], c.months[1]) + trail;
}

// ---- HTML -----------------------------------------------------------------------------------

/** Elements that belong to the sentence around them. */
const INLINE = new Set([
  'a',
  'strong',
  'em',
  'b',
  'i',
  'span',
  'abbr',
  'time',
  'small',
  'mark',
  'sup',
  'sub',
  'br',
  'wbr',
  's',
  'u',
  'q',
  'cite',
  'bdi',
]);
/** Inline elements kept whole, never translated inside. */
const OPAQUE = new Set(['code', 'kbd', 'samp', 'var', 'svg']);
/** Elements whose content is never translated. */
const RAW = new Set(['script', 'style', 'textarea', 'pre']);
const VOID = new Set([
  'br',
  'wbr',
  'img',
  'input',
  'meta',
  'link',
  'hr',
  'source',
  'area',
  'base',
  'col',
  'embed',
  'param',
  'track',
]);
const ATTRIBUTES = /\s(placeholder|aria-label|title|alt)="([^"]*)"/g;

type Token =
  | { kind: 'text'; text: string }
  | { kind: 'tag'; text: string; name: string; close: boolean; selfClose: boolean };

function tokenize(html: string): Token[] {
  const tokens: Token[] = [];
  const re =
    /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/?([a-zA-Z][a-zA-Z0-9-]*)(?:\s(?:[^>"']|"[^"]*"|'[^']*')*)?\/?>/gi;
  let last = 0;
  for (let m = re.exec(html); m; m = re.exec(html)) {
    if (m.index > last) tokens.push({ kind: 'text', text: html.slice(last, m.index) });
    const text = m[0];
    const name = (m[1] ?? '').toLowerCase();
    tokens.push({
      kind: 'tag',
      text,
      name,
      close: text.startsWith('</'),
      selfClose: text.endsWith('/>') || VOID.has(name),
    });
    last = re.lastIndex;
  }
  if (last < html.length) tokens.push({ kind: 'text', text: html.slice(last) });
  return tokens;
}

/** Translates an element's text attributes and, for a submit input, its value. */
function translateTag(tag: string, locale: Locale): string {
  // 2earl.com has every page in every language: /privacy → /tr/privacy.
  let out = tag.replace(
    /\shref="https:\/\/2earl\.com(\/[a-z-]*)?(#[^"]*)?"/,
    (_, path: string | undefined, hash: string | undefined) =>
      ` href="https://2earl.com/${locale}${path && path !== '/' ? path : ''}${hash ?? ''}"`,
  );
  out = out.replace(ATTRIBUTES, (whole, attr: string, value: string) =>
    value ? ` ${attr}="${translate(value, locale)}"` : whole,
  );
  if (/^<input\b/i.test(out) && /\stype="(submit|button)"/.test(out)) {
    out = out.replace(/\svalue="([^"]*)"/, (_, v: string) => ` value="${translate(v, locale)}"`);
  }
  if (/^<meta\b/i.test(out) && /\sname="description"/.test(out)) {
    out = out.replace(
      /\scontent="([^"]*)"/,
      (_, v: string) => ` content="${translate(v, locale)}"`,
    );
  }
  return out;
}

/**
 * Splits a run into its top-level parts: text, and elements with their content. Null when the
 * run's text outside elements is a sentence (then the run is one sentence).
 */
function topLevel(run: Token[], force = false): (Token | Token[])[] | null {
  const items: (Token | Token[])[] = [];
  let current: Token[] | null = null;
  let name = '';
  let depth = 0;
  for (const t of run) {
    if (current) {
      current.push(t);
      if (t.kind === 'tag' && t.name === name && !t.selfClose) depth += t.close ? -1 : 1;
      if (depth === 0) {
        items.push(current);
        current = null;
      }
      continue;
    }
    if (t.kind === 'text') {
      const text = t.text.trim();
      if (!force && text && !keep(text) && text !== '·' && text !== '|') return null;
      items.push(t);
    } else if (t.close) {
      return null;
    } else if (t.selfClose) {
      items.push([t]);
    } else {
      current = [t];
      name = t.name;
      depth = 1;
    }
  }
  if (current) return null;
  const elements = items.filter((i) => Array.isArray(i)).length;
  // Several elements side by side, or one element around everything (look inside it).
  if (elements >= 2 || (force && elements >= 1)) return items;
  if (elements === 1 && items.every((i) => Array.isArray(i) || !i.text.trim())) return items;
  return null;
}

/** A run of text and inline elements, as one sentence. */
function translateRun(run: Token[], c: Compiled, locale: Locale): string {
  const original = run.map((t) => t.text).join('');
  // Elements side by side (a list of links, a name and a tag): each is its own sentence.
  const parts = topLevel(run);
  if (parts) {
    return parts
      .map((part) => {
        if (!Array.isArray(part)) return part.text;
        const [open, ...rest] = part;
        if (!open || rest.length === 0 || isOpaque(open)) {
          return part
            .map((t) => (t.kind === 'tag' && !isOpaque(t) ? translateTag(t.text, locale) : t.text))
            .join('');
        }
        const close = rest.pop();
        return (
          translateTag(open.text, locale) + translateRun(rest, c, locale) + (close?.text ?? '')
        );
      })
      .join('');
  }
  if (!run.some((t) => t.kind === 'text' && /[A-Za-z]{2}/.test(t.text))) {
    return run.map((t) => (t.kind === 'tag' ? translateTag(t.text, locale) : t.text)).join('');
  }
  // Number the elements; opaque ones (with their content) become one marker.
  const markers: string[][] = [];
  const stack: number[] = [];
  let key = '';
  let opaqueName = '';
  let opaqueDepth = 0;
  let opaqueParts: string[] = [];
  for (const t of run) {
    if (opaqueDepth > 0) {
      opaqueParts.push(t.text);
      if (t.kind === 'tag' && t.name === opaqueName && !t.selfClose) {
        opaqueDepth += t.close ? -1 : 1;
      }
      if (opaqueDepth === 0) {
        markers.push(opaqueParts);
        key += `<${String(markers.length - 1)}/>`;
        opaqueParts = [];
      }
      continue;
    }
    if (t.kind === 'text') {
      key += t.text;
    } else if (!t.close && isOpaque(t)) {
      opaqueParts = [t.text];
      if (t.selfClose) {
        markers.push(opaqueParts);
        key += `<${String(markers.length - 1)}/>`;
      } else {
        opaqueName = t.name;
        opaqueDepth = 1;
      }
    } else if (t.selfClose) {
      markers.push([translateTag(t.text, locale)]);
      key += `<${String(markers.length - 1)}/>`;
    } else if (!t.close) {
      markers.push([translateTag(t.text, locale), '']);
      stack.push(markers.length - 1);
      key += `<${String(markers.length - 1)}>`;
    } else {
      const n = stack.pop();
      if (n === undefined) return original;
      const marker = markers[n];
      if (marker) marker[1] = t.text;
      key += `</${String(n)}>`;
    }
  }
  if (stack.length > 0 || opaqueDepth > 0) return original;

  const lead = /^\s*/.exec(key)?.[0] ?? '';
  const trail = /\s*$/.exec(key)?.[0] ?? '';
  let core = key.replace(/\s+/g, ' ').trim();
  // Elements around the whole sentence stay outside it: "<0>Cancel</0>" is looked up as "Cancel".
  const wrappers: number[] = [];
  for (;;) {
    const m = /^<(\d+)>([\s\S]*)<\/(\d+)>$/.exec(core);
    if (!m || m[1] !== m[3] || m[2] === undefined) break;
    wrappers.push(Number(m[1]));
    core = m[2].trim();
  }
  const found = lookup(c, core);
  if (found === null && !keep(core) && wrappers.length === 0) {
    // Not a sentence of the catalog, but elements in it may be: "Ada <0>Owner</0>" is a name
    // and a role. The text between them stays as it is (names), unless the catalog has it.
    const parts = topLevel(run, true);
    if (parts?.some((p) => Array.isArray(p))) {
      return parts
        .map((part) => {
          if (Array.isArray(part)) return translateRun(part, c, locale);
          const text = part.text.replace(/\s+/g, ' ').trim();
          if (!text) return part.text;
          const hit = lookup(c, text);
          if (hit !== null) return part.text.replace(text, hit);
          if (text.split(' ').length > 3 && !keep(text)) miss(text);
          return part.text;
        })
        .join('');
    }
  }
  const sentence = found ?? (keep(core) ? core : miss(core));
  const rebuilt = sentence
    .replace(c.months[0], c.months[1])
    .replace(/<(\d+)\/>/g, (_, n: string) => (markers[Number(n)] ?? []).join(''))
    .replace(/<(\d+)>/g, (_, n: string) => markers[Number(n)]?.[0] ?? '')
    .replace(/<\/(\d+)>/g, (_, n: string) => markers[Number(n)]?.[1] ?? '');
  let wrapped = rebuilt;
  for (const n of wrappers.reverse()) {
    wrapped = `${markers[n]?.[0] ?? ''}${wrapped}${markers[n]?.[1] ?? ''}`;
  }
  return lead + wrapped + trail;
}

/** The page in the language: its sentences, text attributes and `<html lang>`. */
export function localizeHtml(html: string, locale: Locale): string {
  const c = locale === DEFAULT_LOCALE ? null : compile(locale);
  if (!c) return html;
  const tokens = tokenize(html);
  let out = '';
  let run: Token[] = [];
  let raw: string | null = null;
  const flush = () => {
    if (run.length > 0) out += translateRun(run, c, locale);
    run = [];
  };
  for (const t of tokens) {
    if (raw) {
      out += t.text;
      if (t.kind === 'tag' && t.close && t.name === raw) raw = null;
      continue;
    }
    if (t.kind === 'tag' && RAW.has(t.name) && !t.close) {
      flush();
      out += t.text;
      raw = t.name;
      continue;
    }
    if (
      t.kind === 'text' ||
      INLINE.has(t.name) ||
      (!t.close && isOpaque(t)) ||
      (run.length > 0 && inOpaque(run))
    ) {
      run.push(t);
      continue;
    }
    flush();
    if (t.name === 'html' && !t.close) {
      out += t.text.replace(/\slang="[^"]*"/, ` lang="${locale}"`);
    } else {
      out += translateTag(t.text, locale);
    }
  }
  flush();
  return out;
}

/** Elements kept whole: code, svg, and anything marked translate="no". */
function isOpaque(t: Token): boolean {
  return t.kind === 'tag' && (OPAQUE.has(t.name) || /\stranslate="no"/.test(t.text));
}

/** Whether the run ends inside an opaque element (an svg's paths belong to it). */
function inOpaque(run: Token[]): boolean {
  let name = '';
  let depth = 0;
  for (const t of run) {
    if (t.kind !== 'tag' || t.selfClose) continue;
    if (depth === 0) {
      if (!t.close && isOpaque(t)) {
        name = t.name;
        depth = 1;
      }
    } else if (t.name === name) depth += t.close ? -1 : 1;
  }
  return depth > 0;
}
