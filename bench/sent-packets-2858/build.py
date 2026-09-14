"""Build isolated comparison executables; run from this checkout."""
import argparse,json,os,shutil,subprocess
from pathlib import Path
here=Path(__file__).resolve().parent
repo=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],cwd=here,text=True).strip())
parser=argparse.ArgumentParser()
parser.add_argument('--variants',nargs='+',choices=['pr','blocks','packed','successor-final'],default=['pr','blocks','packed'])
parser.add_argument('--prepare-only',action='store_true')
args=parser.parse_args()
local=here/('successor-prepare-check' if args.prepare_only else 'local');local.mkdir(exist_ok=True)
(local/'bin').mkdir(exist_ok=True);(local/'artifacts').mkdir(exist_ok=True)
base='d11d61556d41395aedbde7ff52e0b9e1af25aa42'
for variant in args.variants:
    work=local/variant
    if work.exists():raise SystemExit(f'{work} exists; use a fresh benchmark checkout to preserve prior results')
    subprocess.run(['git','worktree','add','--detach',str(work),base],cwd=repo,check=True)
    if variant!='pr':
        source=(repo/'quinn-proto/src/connection/sent_packets.rs' if variant=='successor-final' else here/f'{variant}-reference.rs')
        shutil.copy2(source,work/'quinn-proto/src/connection/sent_packets.rs')
    if variant=='successor-final':
        shutil.copy2(repo/'quinn-proto/src/connection/spaces.rs',work/'quinn-proto/src/connection/spaces.rs')
    with (work/'quinn-proto/src/connection/mod.rs').open('a') as out:out.write('\n#[cfg(test)]\nmod fedora_bench;\n')
    micro=(here/'micro.rs').read_text()
    probes=(here/'range-positions.rs').read_text()
    if variant=='successor-final':
        old='black_box(&m).range((Bound::Excluded(black_box(0)), Bound::Unbounded)).next()'
        assert micro.count(old)==1
        micro=micro.replace(old,'black_box(&m).first_after(black_box(0))')
        for old,new in [
            ('m.range((Bound::Excluded(query), Bound::Unbounded)).next()','m.first_after(query)'),
            ('black_box(&m).range((Bound::Excluded(black_box(query)), Bound::Unbounded)).next()','black_box(&m).first_after(black_box(query))'),
        ]:
            assert probes.count(old)==1
            probes=probes.replace(old,new)
    micro_path=work/'quinn-proto/src/connection/fedora_bench.rs'
    micro_path.write_text(micro)
    (work/'quinn-proto/src/connection/fedora_range_positions.rs').write_text(probes)
    shutil.copy2(here/'e2e.rs',work/'quinn/benches/fedora.rs')
    with (work/'quinn/Cargo.toml').open('a') as out:out.write('\n[[bench]]\nname = "fedora"\nharness = false\nrequired-features = ["rustls-ring"]\n')
    if args.prepare_only:continue
    env=dict(os.environ,CARGO_TARGET_DIR=str(local/f'target-{variant}'),CARGO_BUILD_JOBS='4')
    for kind,cmd in [('micro',['test','--release','--locked','-p','quinn-proto','--lib','--no-run']),('e2e',['bench','--locked','-p','quinn','--bench','fedora','--no-run']),('range-positions',['test','--release','--locked','-p','quinn-proto','--lib','--no-run'])]:
        if kind=='range-positions':micro_path.write_text(micro+probes)
        log=local/f'artifacts/build-{variant}-{kind}.jsonl'
        with log.open('w') as out,log.with_suffix('.log').open('w') as err:
            subprocess.run(['cargo',*cmd,'--message-format=json'],cwd=work,env=env,stdout=out,stderr=err,check=True)
        items=[json.loads(line) for line in log.read_text().splitlines() if line.startswith('{')]
        executables=[x['executable'] for x in items if x.get('reason')=='compiler-artifact' and x.get('executable') and x['target']['name']==('fedora' if kind=='e2e' else 'quinn_proto')]
        assert len(executables)==1
        shutil.copy2(executables[0],local/f'bin/{variant}-{kind}')
        if kind=='micro':shutil.copy2(executables[0],local/f'bin/{variant}-cleanup-v2')
        print(f'Built {variant}-{kind}',flush=True)
    micro_path.write_text(micro)
