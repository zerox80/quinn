"""Repeat only encrypted transfer comparisons, requiring Firefox to be closed."""
import datetime, hashlib, itertools, json, os, random, subprocess, time
from pathlib import Path
r = Path(__file__).resolve().parent / 'local'
out = r / 'artifacts/packed-control-results.jsonl'
assert not out.exists(), 'Preserve prior observations; choose a fresh directory'
def firefox_browser_pids():
    found = []
    for p in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            argv = p.read_bytes().split(b'\0')
            executable = Path(argv[0].decode(errors='replace')).name if argv and argv[0] else ''
            # Fedora keeps a tiny GNOME D-Bus activation service alive after
            # every Firefox window closes. It is not an interactive browser.
            if executable in ('firefox', 'firefox-bin') and b'--dbus-service' not in argv:
                found.append(int(p.parent.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return found
def context():
    return dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                ac=Path('/sys/class/power_supply/AC/online').read_text().strip(),
                profile=Path('/sys/firmware/acpi/platform_profile').read_text().strip(),
                temp=Path('/sys/class/thermal/thermal_zone9/temp').read_text().strip(),
                firefox_browser_pids=firefox_browser_pids(),
                loadavg=Path('/proc/loadavg').read_text().strip())
assert not firefox_browser_pids(), 'Close interactive Firefox before starting'
orders = list(itertools.permutations(['pr', 'blocks', 'packed'])) * 4
random.Random(285805).shuffle(orders)
manifest = dict(rounds=24, seed=285805, orders=orders, warmup_seconds=1,
                measure_seconds=3, cooldown_seconds=2, client_cpu=0, server_cpu=2,
                socket_buffer_bytes=4194304, transfer_bytes=67108864,
                binaries={v: hashlib.sha256((r/f'bin/{v}-e2e').read_bytes()).hexdigest()
                          for v in ['pr', 'blocks', 'packed']})
(r/'artifacts/packed-control-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
for round, order in enumerate(orders):
    values = []
    for v in order:
        before = context()
        assert before['ac'] == '1' and before['profile'] == 'performance' and not before['firefox_browser_pids']
        env = dict(os.environ, CLIENT_CPU='0', SERVER_CPU='2', SOCKET_BUFFER_BYTES='4194304')
        p = subprocess.Popen(['taskset', '-c', '0', str(r/f'bin/{v}-e2e'), '67108864', '1', '3'],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        guards = []
        while p.poll() is None:
            guard = context()
            guards.append(guard)
            if guard['ac'] != '1' or guard['profile'] != 'performance' or guard['firefox_browser_pids']:
                p.terminate()
                break
            time.sleep(.1)
        stdout, stderr = p.communicate(timeout=10)
        (r/f'artifacts/packed-control-{round}-{v}.log').write_text(stdout+stderr)
        after = context()
        assert p.returncode == 0, (v, stderr)
        assert all(g['ac'] == '1' and g['profile'] == 'performance' and not g['firefox_browser_pids'] for g in [before, *guards, after])
        results = [json.loads(line.split('RESULT ', 1)[1]) for line in stdout.splitlines() if 'RESULT ' in line]
        assert len(results) == 1 and results[0]['lost_packets'] == 0
        row = dict(variant=v, kind='e2e', case='64MiB', round=round, order=order,
                   before=before, after=after, guard_samples=guards, data=results[0])
        with out.open('a') as f:
            f.write(json.dumps(row)+'\n')
        values.append(f'{v}={results[0]["gbit_s"]:.3f} Gbit/s')
        time.sleep(2)
    print(f'Control round {round+1}/24: '+', '.join(values), flush=True)
print('Completed 72 transfer processes with interactive Firefox absent and AC/performance guarded.', flush=True)
