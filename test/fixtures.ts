import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function loadDigFixture(name: string): string[][] {
  const raw = readFileSync(join(process.cwd(), 'test', 'fixtures', `${name}.txt`), 'utf8');
  return raw.trim().split(/\r?\n/).map((line) => {
    const chunks = [...line.matchAll(/"((?:\\.|[^"\\])*)"/g)].map((match) => JSON.parse(`"${match[1]}"`) as string);
    if (chunks.length === 0) {
      throw new Error(`fixture line contains no TXT chunks: ${line}`);
    }
    return chunks;
  });
}
