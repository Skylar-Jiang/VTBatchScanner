import { Alert, AlertDescription, AlertTitle } from './ui/alert';
import { Button } from './ui/button';

export function LocalDataState({error, loading, reload}: {error: string | null; loading: boolean; reload: () => void}) {
  if (error) return <Alert variant="destructive"><AlertTitle>数据读取失败</AlertTitle><AlertDescription>{error}<Button size="sm" variant="outline" onClick={reload}>重试本地读取</Button></AlertDescription></Alert>;
  if (loading) return <p role="status" className="text-sm text-muted-foreground">正在读取本地报告…</p>;
  return null;
}
