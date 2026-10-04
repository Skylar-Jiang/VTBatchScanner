import { expect, it } from 'vitest';
import { sampleRow, type StoredSample } from './workspace';

it('uses latest provider report filename after an earlier failure',()=>{
  const value={sha256:'a'.repeat(64),risk:'malicious',status:'completed',lastAnalysisAt:null,riskSources:['virustotal'],providerStatuses:{virustotal:'success',cn_platform:'not_supported'},providerResults:[
    {provider:'virustotal',status:'failed',report:null,error:'timeout',queriedAt:null,fromCache:false},
    {provider:'virustotal',status:'success',report:{fileName:'latest.exe'},error:null,queriedAt:null,fromCache:false}
  ]} as StoredSample;
  expect(sampleRow(value).fileName).toBe('latest.exe');
});
