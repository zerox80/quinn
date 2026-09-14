from pathlib import Path
import datetime,json,os,subprocess,time
r=Path(__file__).resolve().parent / 'local'
out=r/'artifacts/packed-cleanup-v2-results.jsonl';assert not out.exists()
def context():return dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),ac=Path('/sys/class/power_supply/AC/online').read_text().strip(),profile=Path('/sys/firmware/acpi/platform_profile').read_text().strip(),temp=Path('/sys/class/thermal/thermal_zone9/temp').read_text().strip())
for entry in ['cleanup_comparison','fragmented_memory']:
    for v in ['pr','blocks','packed']:
        before=context();assert before['ac']=='1' and before['profile']=='performance'
        proc=subprocess.Popen(['taskset','-c','4',str(r/f'bin/{v}-micro'),'--exact',f'connection::fedora_bench::{entry}','--ignored','--nocapture','--test-threads=1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        on_ac=True
        while proc.poll() is None:
            if context()['ac']!='1':on_ac=False;proc.terminate();break
            time.sleep(.05)
        stdout,stderr=proc.communicate(timeout=10)
        (r/f'artifacts/packed-cleanup-v2-{entry}-{v}.log').write_text(stdout+stderr)
        after=context();assert on_ac and after['ac']=='1' and after['profile']=='performance' and proc.returncode==0,(stdout,stderr)
        rows=[json.loads(x.split('RESULT ',1)[1]) for x in stdout.splitlines() if 'RESULT ' in x]
        assert len(rows)==(18 if entry=='cleanup_comparison' else 1)
        for row in rows:
            with out.open('a') as f:f.write(json.dumps(dict(variant=v,kind=entry,before=before,after=after,data=row))+'\n')
        print(entry,v,'passed',flush=True)
