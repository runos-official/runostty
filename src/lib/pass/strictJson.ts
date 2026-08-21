/**
 * A strict JSON reader for signed credentials.
 *
 * WHY THIS EXISTS AND JSON.parse DOES NOT DO. Two things a pass decoder must see, both of which
 * JSON.parse destroys before returning:
 *
 * 1. DUPLICATE KEYS. `JSON.parse('{"kind":"ws.files","kind":"vm.ssh"}')` returns one value and says
 *    nothing about the other. Go's encoding/json also keeps the last, so the two languages happen to
 *    agree today, but that agreement is incidental: JSON itself does not specify it, and a payload
 *    where one verifier reads one value and the other reads the other is a forgery that verifies.
 *    Refusing the shape removes the class rather than relying on two parsers staying in step.
 *
 * 2. THE NUMBER LITERAL. `JSON.parse('{"exp":1.75580006e9}').exp` is 1755800060, indistinguishable
 *    from the integer. Go refuses that literal into an int64. Keeping the literal text is what lets
 *    both sides refuse it identically. MEASURED 2026-08-21: the reverse case bit first, where Go
 *    ACCEPTED the JSON string "1755800060" into a json.Number and JavaScript would not.
 *
 * It is deliberately small and total: it parses the subset a pass payload may contain and refuses
 * everything else, rather than being a general JSON library.
 */

export class StrictJsonError extends Error {}

export interface StrictObject {
  /** The parsed value, with objects as plain records. */
  readonly value: Record<string, unknown>;
  /** Raw literal text for every number, keyed by dotted path, e.g. "exp" or "vm.port". */
  readonly numberLiterals: ReadonlyMap<string, string>;
}

/** Parse a pass payload. Throws StrictJsonError with a short reason on anything unusual. */
export function parseStrictObject(text: string): StrictObject {
  const p = new Parser(text);
  p.skipWhitespace();
  const value = p.parseValue('');
  p.skipWhitespace();
  if (!p.atEnd()) {
    // Bytes after the object were covered by the signature and read by nobody.
    throw new StrictJsonError('trailing content after the value');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new StrictJsonError('not a JSON object');
  }
  return { value: value as Record<string, unknown>, numberLiterals: p.numbers };
}

class Parser {
  private i = 0;
  readonly numbers = new Map<string, string>();

  constructor(private readonly s: string) {}

  atEnd(): boolean {
    return this.i >= this.s.length;
  }

  skipWhitespace(): void {
    while (this.i < this.s.length && (this.s[this.i] === ' ' || this.s[this.i] === '\t' || this.s[this.i] === '\n' || this.s[this.i] === '\r')) {
      this.i++;
    }
  }

  parseValue(path: string): unknown {
    this.skipWhitespace();
    if (this.atEnd()) throw new StrictJsonError('unexpected end of payload');
    const c = this.s[this.i];
    if (c === '{') return this.parseObject(path);
    if (c === '[') return this.parseArray(path);
    if (c === '"') return this.parseString();
    if (c === 't' || c === 'f' || c === 'n') return this.parseLiteral();
    return this.parseNumber(path);
  }

  private parseObject(path: string): Record<string, unknown> {
    this.expect('{');
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.s[this.i] === '}') {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.s[this.i] !== '"') throw new StrictJsonError('object keys must be strings');
      const key = this.parseString();
      if (seen.has(key)) {
        throw new StrictJsonError(`the payload names "${key}" more than once`);
      }
      seen.add(key);
      this.skipWhitespace();
      this.expect(':');
      out[key] = this.parseValue(path ? `${path}.${key}` : key);
      this.skipWhitespace();
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        continue;
      }
      if (c === '}') {
        this.i++;
        return out;
      }
      throw new StrictJsonError('malformed object');
    }
  }

  private parseArray(path: string): unknown[] {
    this.expect('[');
    const out: unknown[] = [];
    this.skipWhitespace();
    if (this.s[this.i] === ']') {
      this.i++;
      return out;
    }
    for (;;) {
      out.push(this.parseValue(`${path}[${out.length}]`));
      this.skipWhitespace();
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        continue;
      }
      if (c === ']') {
        this.i++;
        return out;
      }
      throw new StrictJsonError('malformed array');
    }
  }

  private parseString(): string {
    this.expect('"');
    let out = '';
    for (;;) {
      if (this.atEnd()) throw new StrictJsonError('unterminated string');
      const c = this.s[this.i];
      if (c === '"') {
        this.i++;
        return out;
      }
      if (c === '\\') {
        this.i++;
        const e = this.s[this.i];
        this.i++;
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const hex = this.s.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new StrictJsonError('bad unicode escape');
            out += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default:
            throw new StrictJsonError('bad string escape');
        }
        continue;
      }
      const code = c.charCodeAt(0);
      if (code < 0x20) throw new StrictJsonError('a raw control character in a string');
      out += c;
      this.i++;
    }
  }

  private parseNumber(path: string): number {
    const start = this.i;
    if (this.s[this.i] === '-') this.i++;
    while (this.i < this.s.length && /[0-9eE+.\-]/.test(this.s[this.i])) this.i++;
    const literal = this.s.slice(start, this.i);
    if (literal === '' || !/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/.test(literal)) {
      throw new StrictJsonError('malformed number');
    }
    // The LITERAL is what the caller checks. The parsed value is only for fields where any number
    // would do, and a pass has none of those.
    this.numbers.set(path, literal);
    return Number(literal);
  }

  private parseLiteral(): boolean | null {
    for (const [word, value] of [['true', true], ['false', false], ['null', null]] as const) {
      if (this.s.startsWith(word, this.i)) {
        this.i += word.length;
        return value;
      }
    }
    throw new StrictJsonError('unexpected token');
  }

  private expect(c: string): void {
    if (this.s[this.i] !== c) throw new StrictJsonError(`expected ${c}`);
    this.i++;
  }
}
