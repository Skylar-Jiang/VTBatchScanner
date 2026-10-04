import { useCallback, useEffect, useState } from 'react';
import { getLocalData } from '@/api/workspace';

// Only polls this local API: opening a page never sends a VirusTotal query.
export function useLocalData<T>(path: string, isActive?: (data: T) => boolean) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision(value => value + 1), []);
  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function load() {
      try {
        const result = await getLocalData<T>(path);
        if (disposed) return;
        setData(result); setError(null); setUpdatedAt(new Date().toLocaleString());
        if (isActive?.(result)) timer = setTimeout(() => { if (document.hidden) timer = setTimeout(load, 5000); else void load(); }, 5000);
      } catch {
        if (!disposed) setError('无法读取本地数据；已保留上次结果，请检查后端并重试。');
      }
    }
    void load();
    return () => { disposed = true; clearTimeout(timer); };
  }, [path, revision, isActive]);
  return {data, error, updatedAt, reload};
}
