import collections,json,math,random,statistics
from pathlib import Path
r=Path(__file__).resolve().parent / 'local'
rows=[json.loads(x) for x in (r/'artifacts/packed-results.jsonl').read_text().splitlines()]
assert len(rows)==129 and len({(x['kind'],x['case'],x['round'],x['variant']) for x in rows})==129
assert all(x[p]['ac']=='1' and x[p]['profile']=='performance' for x in rows for p in ['before','after'])
rng=random.Random(285804);groups=collections.defaultdict(list);summary=[]
for x in rows:groups[(x['kind'],x['case'])].append(x)
for (kind,case),group in groups.items():
    if kind=='memory':
        summary.append(dict(kind=kind,case=case,variants={x['variant']:x['data'] for x in group}));continue
    for metric in (['gbit_s','cpu_ns_byte'] if kind=='e2e' else ['ns_op']):
        data={v:{x['round']:x['data'][metric] for x in group if x['variant']==v} for v in ['pr','blocks','packed']}
        comparisons={}
        for ref in ['pr','blocks']:
            logs=[math.log(data['packed'][i]/data[ref][i]) for i in sorted(data['packed'])]
            boot=sorted(math.exp(statistics.mean(rng.choices(logs,k=len(logs)))) for _ in range(10000))
            comparisons[f'packed/{ref}']={'ratio':math.exp(statistics.mean(logs)),'ci95':[boot[250],boot[9749]]}
        summary.append(dict(kind=kind,case=case,metric=metric,medians={v:statistics.median(d.values()) for v,d in data.items()},comparisons=comparisons))
result=dict(processes=129,ac='1',profile='performance',temperature_c=[min(int(x[p]['temp'])/1000 for x in rows for p in ['before','after']),max(int(x[p]['temp'])/1000 for x in rows for p in ['before','after'])],results=summary)
(r/'artifacts/packed-summary.json').write_text(json.dumps(result,indent=2)+'\n')
for s in summary:
    print(s)
