// Automat kontekstu HTML dla podpowiedzi napraw XSS.
// Wejściem jest tekst HTML sprzed miejsca, w którym wypisujemy dane. Wynik mówi,
// jaka funkcja ucieczki pasuje. W razie wątpliwości zwracamy 'unsafe', czyli
// brak podpowiedzi. Lepiej nic nie podpowiedzieć niż podpowiedzieć złą ucieczkę.

export type XssContext =
  | { kind: 'text' }
  | { kind: 'attr'; quote: '"' | "'"; name: string; atStart: boolean }
  | { kind: 'unsafe' };

type State =
  | 'text'
  | 'tagname'
  | 'intag'
  | 'attrname'
  | 'afterattrname'
  | 'afterequals'
  | 'valuedq'
  | 'valuesq'
  | 'valueunq'
  | 'comment'
  | 'rawtext';

const RAW_TEXT_TAGS = new Set(['script', 'style']);
const NAME_CHAR = /[A-Za-z0-9:_.-]/;
const LETTER = /[A-Za-z]/;
const SPACE = /\s/;

interface Scan {
  state: State;
  rawTag: string; // nazwa znacznika script albo style, gdy state to 'rawtext'
  attr: string;
  valueLen: number;
}

// Przebieg automatu po tekście sprzed miejsca wypisania danych.
function scan(prefix: string): Scan {
  let state: State = 'text';
  let tag = '';
  let closing = false;
  let rawTag = '';
  let attr = '';
  let valueLen = 0;

  const endTag = (): State => {
    if (!closing && RAW_TEXT_TAGS.has(tag)) {
      rawTag = tag;
      return 'rawtext';
    }
    return 'text';
  };

  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix[i];
    switch (state) {
      case 'text':
        if (ch === '<') {
          if (prefix.startsWith('<!--', i)) {
            state = 'comment';
            i += 3;
          } else if (LETTER.test(prefix[i + 1] ?? '')) {
            state = 'tagname';
            tag = '';
            closing = false;
          } else if (prefix[i + 1] === '/' && LETTER.test(prefix[i + 2] ?? '')) {
            state = 'tagname';
            tag = '';
            closing = true;
            i += 1;
          }
        }
        break;
      case 'rawtext':
        if (ch === '<' && prefix[i + 1] === '/' && prefix.slice(i + 2, i + 2 + rawTag.length).toLowerCase() === rawTag) {
          state = 'tagname';
          tag = '';
          closing = true;
          i += 1;
        }
        break;
      case 'comment':
        if (prefix.startsWith('-->', i)) {
          state = 'text';
          i += 2;
        }
        break;
      case 'tagname':
        if (NAME_CHAR.test(ch)) tag += ch.toLowerCase();
        else if (ch === '>') state = endTag();
        else state = 'intag';
        break;
      case 'intag':
        if (ch === '>') state = endTag();
        else if (!SPACE.test(ch) && ch !== '/') {
          attr = ch.toLowerCase();
          state = 'attrname';
        }
        break;
      case 'attrname':
        if (ch === '=') state = 'afterequals';
        else if (ch === '>') state = endTag();
        else if (SPACE.test(ch)) state = 'afterattrname';
        else if (ch === '/') state = 'intag';
        else attr += ch.toLowerCase();
        break;
      case 'afterattrname':
        if (ch === '=') state = 'afterequals';
        else if (ch === '>') state = endTag();
        else if (!SPACE.test(ch)) {
          attr = ch.toLowerCase();
          state = 'attrname';
        }
        break;
      case 'afterequals':
        if (ch === '"') {
          state = 'valuedq';
          valueLen = 0;
        } else if (ch === "'") {
          state = 'valuesq';
          valueLen = 0;
        } else if (ch === '>') state = endTag();
        else if (!SPACE.test(ch)) state = 'valueunq';
        break;
      case 'valuedq':
        if (ch === '"') state = 'intag';
        else valueLen++;
        break;
      case 'valuesq':
        if (ch === "'") state = 'intag';
        else valueLen++;
        break;
      case 'valueunq':
        if (ch === '>') state = endTag();
        else if (SPACE.test(ch)) state = 'intag';
        break;
    }
  }

  return { state, rawTag, attr, valueLen };
}

export function contextAt(prefix: string): XssContext {
  const { state, attr, valueLen } = scan(prefix);
  if (state === 'text') return { kind: 'text' };
  if (state === 'valuedq') return { kind: 'attr', quote: '"', name: attr, atStart: valueLen === 0 };
  if (state === 'valuesq') return { kind: 'attr', quote: "'", name: attr, atStart: valueLen === 0 };
  return { kind: 'unsafe' };
}

// Funkcje takie jak sanitize_text_field i strip_tags usuwają znaczniki, ale zostawiają cudzysłowy i nawiasy
// w tekście. W treści strony to wystarcza. W atrybucie, w znaczniku i w skrypcie wartość wychodzi poza swoje miejsce.
// Komentarz i styl uznajemy za bezpieczne, bo bez znaczników nie da się z nich wyjść do wykonania kodu.
export function textSanitizerExposure(prefix: string): 'covered' | 'exposed' {
  const { state, rawTag } = scan(prefix);
  if (state === 'text' || state === 'comment') return 'covered';
  if (state === 'rawtext') return rawTag === 'script' ? 'exposed' : 'covered';
  return 'exposed';
}

// Atrybuty, których wartość jest adresem URL.
const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'poster', 'cite']);

export type Escaper = 'esc_html' | 'esc_attr' | 'esc_url';

// Dobiera funkcję ucieczki do kontekstu. nextChar to pierwszy znak tekstu po
// wypisywanej wartości (pusty, gdy nieznany). Zwraca null, gdy nie ma bezpiecznego wyboru.
export function chooseEscaper(ctx: XssContext, nextChar: string): Escaper | null {
  if (ctx.kind === 'text') return 'esc_html';
  if (ctx.kind === 'unsafe') return null;
  const name = ctx.name;
  // Zdarzenia (onclick i podobne) i style to konteksty JavaScript i CSS. Tam esc_attr nie wystarcza.
  if (name.startsWith('on') || name === 'style') return null;
  if (URL_ATTRS.has(name)) {
    if (!ctx.atStart) return 'esc_attr';
    // Cały adres to jedna wartość: esc_url pasuje tylko, gdy zaraz po niej kończy się atrybut.
    return nextChar === ctx.quote ? 'esc_url' : null;
  }
  return 'esc_attr';
}
