"""Matched successor comparison; use --analyze-only to replay saved observations."""
import datetime
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

r = Path(__file__).resolve().parent / 'local'
phase = sys.argv[1]
candidate = 'successor-final'
analyze_only = '--analyze-only' in sys.argv[2:]
assert phase in ('micro', 'transfer', 'cleanup', 'positions')
out = r / f'artifacts/{candidate}-{phase}-results.jsonl'
assert analyze_only or not out.exists(), 'Preserve prior observations; use a fresh checkout'
variants = ['pr', 'packed', candidate]
orders = list(itertools.permutations(variants))
random.Random(285806).shuffle(orders)

def context():
    return dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                ac=Path('/sys/class/power_supply/AC/online').read_text().strip(),
                profile=Path('/sys/firmware/acpi/platform_profile').read_text().strip(),
                temp=Path('/sys/class/thermal/thermal_zone9/temp').read_text().strip())

def run(v, case, round, order):
    env = dict(os.environ)
    if phase == 'transfer':
        binary = r / f'bin/{v}-e2e'
        cmd = ['taskset', '-c', '0', str(binary), '67108864', '1', '3']
        env.update(CLIENT_CPU='0', SERVER_CPU='2', SOCKET_BUFFER_BYTES='4194304')
    else:
        suffix = 'range-positions' if phase == 'positions' else ('cleanup-v2' if phase == 'cleanup' and v != candidate else 'micro')
        binary = r / f'bin/{v}-{suffix}'
        entry = 'range_positions' if phase == 'positions' else (case if phase == 'cleanup' else ('selective' if case.startswith(('random','selective')) else 'measure'))
        cmd = ['taskset', '-c', '4', str(binary), '--exact', f'connection::fedora_bench::{entry}', '--ignored', '--nocapture', '--test-threads=1']
        env.update(BENCH_CASE=case, BENCH_SECONDS='0.6')
    before = context()
    assert before['ac'] == '1' and before['profile'] == 'performance'
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    guards = []
    while p.poll() is None:
        g = context()
        guards.append(g)
        if g['ac'] != '1' or g['profile'] != 'performance':
            p.terminate()
            break
        time.sleep(.1)
    stdout, stderr = p.communicate(timeout=10)
    after = context()
    (r/f'artifacts/{candidate}-{phase}-{round}-{case}-{v}.log').write_text(stdout+stderr)
    assert p.returncode == 0, stderr
    assert all(g['ac'] == '1' and g['profile'] == 'performance' for g in [before, *guards, after])
    data = [json.loads(line.split('RESULT ', 1)[1]) for line in stdout.splitlines() if 'RESULT ' in line]
    assert len(data) == (18 if case == 'cleanup_comparison' else 1)
    if phase == 'transfer':
        assert data[0]['lost_packets'] == 0
    with out.open('a') as f:
        for d in data:
            f.write(json.dumps(dict(variant=v, case=case, round=round, order=order, before=before, after=after, guards=guards, data=d))+'\n')
    return data

cases = ['successor_65536', 'dense_1024_32_meta', 'dense_16384_32', 'random_16384', 'selective_16384'] if phase == 'micro' else (['64MiB'] if phase == 'transfer' else (['head','middle','tail','past_end','fragmented_middle','short_head','full_scan'] if phase == 'positions' else ['cleanup_comparison','fragmented_memory']))
round_orders = orders * (2 if phase == 'transfer' else 1) if phase != 'cleanup' else [variants]
for round, order in enumerate([] if analyze_only else round_orders):
    for case in cases:
        for v in order:
            run(v, case, round, order)
            if phase == 'transfer':
                time.sleep(2)
    print(f'{phase}: round {round+1}/{len(round_orders)} complete', flush=True)

rows = [json.loads(line) for line in out.read_text().splitlines()]
expected_rows = 57 if phase=='cleanup' else len(round_orders)*len(cases)*len(variants)
assert len(rows)==expected_rows
assert len({(x['variant'],x['round'],x['case'],x['data'].get('case'),x['data'].get('window')) for x in rows})==expected_rows
assert {x['variant'] for x in rows}==set(variants)
assert all(g['ac']=='1' and g['profile']=='performance' for x in rows for g in [x['before'],*x['guards'],x['after']])
if phase=='transfer':assert all(x['data']['lost_packets']==0 for x in rows)
results = []
rng = random.Random(285806)
if phase != 'cleanup':
    for case in cases:
        for metric in (['gbit_s','cpu_ns_byte'] if phase == 'transfer' else ['ns_op']):
            data = {v:{x['round']:x['data'][metric] for x in rows if x['variant']==v and x['case']==case} for v in variants}
            comparisons = {}
            for ref in ['pr','packed']:
                logs = [math.log(data[candidate][i]/data[ref][i]) for i in sorted(data[ref])]
                boot = sorted(math.exp(statistics.mean(rng.choices(logs,k=len(logs)))) for _ in range(10000))
                comparisons[f'{candidate}/{ref}'] = dict(ratio=math.exp(statistics.mean(logs)),ci95=[boot[250],boot[9749]])
            results.append(dict(case=case,metric=metric,medians={v:statistics.median(d.values()) for v,d in data.items()},comparisons=comparisons))
else:
    for x in rows:
        d=x['data']
        if 'samples_ns' in d:
            results.append(dict(variant=x['variant'],case=d['case'],window=d['window'],median_ns=statistics.median(d['samples_ns']),max_ns=max(d['samples_ns'])))
        else:
            results.append(dict(variant=x['variant'],**d))
summary = dict(phase=phase,processes=len(round_orders)*len(cases)*3,results=results)
(r/f'artifacts/{candidate}-{phase}-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
for x in results:
    print(x,flush=True)
