from pathlib import Path
import json,statistics
r=Path(__file__).resolve().parent / 'local'
rows=[json.loads(x) for x in (r/'artifacts/packed-cleanup-v2-results.jsonl').read_text().splitlines()]
assert len(rows)==57 and all(x[p]['ac']=='1' and x[p]['profile']=='performance' for x in rows for p in ['before','after'])
out=[]
for row in rows:
    x=row['data']
    if row['kind']=='fragmented_memory':out.append(dict(variant=row['variant'],kind=row['kind'],**x));continue
    samples=x['samples_ns'];assert len(samples)==32
    out.append(dict(variant=row['variant'],kind=row['kind'],case=x['case'],window=x['window'],median_ns=statistics.median(samples),p95_ns=sorted(samples)[30],max_ns=max(samples)))
(r/'artifacts/packed-cleanup-v2-summary.json').write_text(json.dumps(out,indent=2)+'\n')
for x in out:
    if x['kind']=='fragmented_memory' or x.get('window')==65536:print(x)
