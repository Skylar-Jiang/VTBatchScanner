import { expect, it } from 'vitest';
import { importHashes } from './import-hashes';
it('imports CSV with sha256 column and quoted values', () => {
  expect(importHashes('name,sha256\n"a,b","'+'A'.repeat(64)+'"','csv')).toEqual(['A'.repeat(64)]);
});
it('requires CSV sha256 column', () => {
  expect(()=>importHashes('name,hash\nx,abc','csv')).toThrow('sha256');
});
it('reads UTF8 BOM TXT lines', () => {
  expect(importHashes('\ufeff'+'a'.repeat(64)+'\r\n','txt')).toEqual(['a'.repeat(64),'']);
});
