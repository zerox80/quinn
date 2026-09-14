import collections, json, math, random, statistics
from pathlib import Path
r = Path(__file__).resolve().parent / 'local'
rows = [json.loads(line) for line in (r/'artifacts/packed-control-results.jsonl').read_text().splitlines()]
assert len(rows) == 72 and len({(x['variant'], x['round']) for x in rows}) == 72
assert all(g['ac'] == '1' and g['profile'] == 'performance' and not g['firefox_browser_pids']
           for x in rows for g in [x['before'], *x['guard_samples'], x['after']])
assert all(x['data']['lost_packets'] == 0 for x in rows)
orders = collections.Counter(tuple(x['order']) for x in rows if x['variant'] == 'pr')
assert len(orders) == 6 and set(orders.values()) == {4}
rng = random.Random(285805)
results = []
for metric in ['gbit_s', 'cpu_ns_byte']:
    data = {v: {x['round']: x['data'][metric] for x in rows if x['variant'] == v}
            for v in ['pr', 'blocks', 'packed']}
    comparisons = {}
    for ref in ['pr', 'blocks']:
        logs = [math.log(data['packed'][i]/data[ref][i]) for i in sorted(data['packed'])]
        boot = sorted(math.exp(statistics.mean(rng.choices(logs, k=len(logs)))) for _ in range(10000))
        comparisons[f'packed/{ref}'] = dict(ratio=math.exp(statistics.mean(logs)), ci95=[boot[250], boot[9749]])
    results.append(dict(metric=metric, medians={v: statistics.median(d.values()) for v,d in data.items()}, comparisons=comparisons))
temps = [int(g['temp'])/1000 for x in rows for g in [x['before'], *x['guard_samples'], x['after']]]
result = dict(processes=72, rounds=24, interactive_firefox_absent=True, ac='1', profile='performance', temperature_c=[min(temps),max(temps)], results=results)
(r/'artifacts/packed-control-summary.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
