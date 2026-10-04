export function importHashes(input: string, format: 'txt' | 'csv'): string[] {
  input = input.replace(/^\uFEFF/, '');
  if (format === 'txt') return input.split(/\r?\n/);
  const rows: string[][] = [[]];
  let cell = '', quoted = false;
  for (let index = 0; index < input.length; index++) {
    const char = input[index];
    if (char === '"') {
      if (quoted && input[index + 1] === '"') { cell += '"'; index++; }
      else quoted = !quoted;
    } else if (!quoted && (char === ',' || char === '\n')) {
      rows[rows.length - 1].push(cell.replace(/\r$/, '')); cell = '';
      if (char === '\n') rows.push([]);
    } else cell += char;
  }
  if (quoted) throw new Error('CSV 引号未闭合');
  rows[rows.length - 1].push(cell.replace(/\r$/, ''));
  const column = rows[0].findIndex(header => header.trim().toLowerCase() === 'sha256');
  if (column < 0) throw new Error('CSV 必须含 sha256 列');
  return rows.slice(1).filter(row => row.some(value => value.trim())).map(row => row[column] ?? '');
}
