import datetime,itertools,json,os,subprocess,time,random
from pathlib import Path
r=Path(__file__).resolve().parent / 'local'
out=r/'artifacts/packed-results.jsonl'
assert not out.exists()
def context():
    return {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ac':Path('/sys/class/power_supply/AC/online').read_text().strip(),'profile':Path('/sys/firmware/acpi/platform_profile').read_text().strip(),'temp':Path('/sys/class/thermal/thermal_zone9/temp').read_text().strip()}
def invoke(v,kind,case,round,order):
    before=context();assert before['ac']=='1' and before['profile']=='performance'
    env=dict(os.environ)
    if kind=='e2e':
        cmd=['taskset','-c','0',str(r/f'bin/{v}-e2e'),'67108864','1','3']
        env.update(CLIENT_CPU='0',SERVER_CPU='2',SOCKET_BUFFER_BYTES='4194304')
    else:
        entry='selective' if case.startswith(('random','selective')) else ('memory' if kind=='memory' else 'measure')
        cmd=['taskset','-c','4',str(r/f'bin/{v}-micro'),'--exact',f'connection::fedora_bench::{entry}','--ignored','--nocapture','--test-threads=1']
        env.update(BENCH_CASE=case,BENCH_SECONDS='0.35',MEMORY_MODE='sparse',MEMORY_SPAN='1048576')
    p=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    on_ac=True
    while p.poll() is None:
        if context()['ac']!='1':on_ac=False;p.terminate();break
        time.sleep(.1)
    stdout,stderr=p.communicate(timeout=10)
    (r/f'artifacts/packed-{kind}-{case}-{round}-{v}.log').write_text(stdout+stderr)
    after=context();assert on_ac and after['ac']=='1' and after['profile']=='performance'
    assert p.returncode==0,(v,stderr)
    result=[json.loads(line.split('RESULT ',1)[1]) for line in stdout.splitlines() if 'RESULT ' in line]
    assert len(result)==1
    if kind=='e2e':assert result[0]['lost_packets']==0
    row=dict(variant=v,kind=kind,case=case,round=round,order=order,before=before,after=after,data=result[0])
    with out.open('a') as f:f.write(json.dumps(row)+'\n')
    return row
orders=list(itertools.permutations(['pr','blocks','packed']))
rng=random.Random(285804)
for round,order in enumerate(orders):
    cases=['dense_1024_32_meta','dense_16384_32','random_16384','selective_16384','successor_65536']
    rng.shuffle(cases)
    for case in cases:
        for v in order:invoke(v,'micro',case,round,order)
    print(f'Micro round {round+1}/6 complete',flush=True)
for v in orders[0]:invoke(v,'memory','sparse_1048576',0,orders[0])
for round,order in enumerate(orders*2):
    values=[]
    for v in order:
        result=invoke(v,'e2e','64MiB',round,order)
        values.append(f'{v}={result["data"]["gbit_s"]:.3f} Gbit/s')
        time.sleep(2)
    print(f'Transfer round {round+1}/12 '+', '.join(values),flush=True)
print('Completed 129 processes, AC-guarded throughout.',flush=True)
