// Generator diffu w formacie unified, zgodnego z git apply.
// Nasze zmiany nie dodają ani nie usuwają znaków nowej linii, więc liczba linii
// przed i po jest ta sama. Wystarczy porównać linie o tych samych numerach.
const CONTEXT = 3;

function splitLines(text: string): { lines: string[]; endsWithNewline: boolean } {
  const endsWithNewline = text.endsWith('\n');
  const body = endsWithNewline ? text.slice(0, -1) : text;
  // Zostawiamy \r na końcu linii, żeby diff zgadzał się z plikiem CRLF.
  return { lines: body.split('\n'), endsWithNewline };
}

interface Hunk {
  from: number; // pierwsza linia hunka (indeks od 0)
  to: number; // ostatnia linia hunka włącznie
}

export function renderUnifiedDiff(file: string, before: string, after: string): string {
  if (before === after) return '';
  const a = splitLines(before);
  const b = splitLines(after);
  if (a.lines.length !== b.lines.length) {
    throw new Error('diff: zmiana nie może zmieniać liczby linii');
  }

  const changed: number[] = [];
  for (let i = 0; i < a.lines.length; i++) if (a.lines[i] !== b.lines[i]) changed.push(i);

  // Zlewamy sąsiednie zmiany we wspólne hunki z kontekstem.
  const hunks: Hunk[] = [];
  for (const i of changed) {
    const from = Math.max(0, i - CONTEXT);
    const to = Math.min(a.lines.length - 1, i + CONTEXT);
    const last = hunks[hunks.length - 1];
    if (last && from <= last.to + 1) last.to = Math.max(last.to, to);
    else hunks.push({ from, to });
  }

  const out: string[] = [`--- a/${file}`, `+++ b/${file}`];
  const lastIndex = a.lines.length - 1;
  const marker = (i: number): string =>
    i === lastIndex && !a.endsWithNewline ? '\n\\ No newline at end of file' : '';

  for (const h of hunks) {
    const count = h.to - h.from + 1;
    out.push(`@@ -${h.from + 1},${count} +${h.from + 1},${count} @@`);
    // Sąsiednie zmienione linie zapisujemy jak git: najpierw usunięte, potem dodane.
    let i = h.from;
    while (i <= h.to) {
      if (a.lines[i] === b.lines[i]) {
        out.push(` ${a.lines[i]}${marker(i)}`);
        i++;
        continue;
      }
      let end = i;
      while (end + 1 <= h.to && a.lines[end + 1] !== b.lines[end + 1]) end++;
      for (let k = i; k <= end; k++) out.push(`-${a.lines[k]}${marker(k)}`);
      for (let k = i; k <= end; k++) out.push(`+${b.lines[k]}${marker(k)}`);
      i = end + 1;
    }
  }
  return out.join('\n') + '\n';
}
