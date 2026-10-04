/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { sha256Bytes } from './hash-file';

it('computes lowercase SHA256 from bytes without upload or execution', async () => {
  vi.stubGlobal('crypto', webcrypto);
  expect(await sha256Bytes(new TextEncoder().encode('abc').buffer)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  vi.unstubAllGlobals();
});
