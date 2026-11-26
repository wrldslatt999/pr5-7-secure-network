"""On-demand HTTP vs certificate-verified HTTPS measurements (real traffic)."""
import argparse
import csv
import datetime
import json
import pathlib
import platform
import statistics
import time

from client.client import send_request, DEFAULT_HTTP, DEFAULT_HTTPS, DEFAULT_CA


def percentile(seq, p):
    seq=sorted(seq)
    idx=(len(seq)-1)*p
    low=int(idx)
    high=min(low+1,len(seq)-1)
    return seq[low]+(seq[high]-seq[low])*(idx-low)


def run(n=20, sizes=(16,1024,2048), http=DEFAULT_HTTP, https=DEFAULT_HTTPS, ca=DEFAULT_CA, output='benchmarks'):
    if n < 5 or n > 200 or any(not 1 <= s <= 4096 for s in sizes):
        raise ValueError('n must be 5..200; sizes must be 1..4096 bytes')
    # Warm each origin prior to measurement; identical endpoint/payload; each request opens a connection.
    for base in (http,https):
        code,_=send_request(base,'/echo-http',{'msg':'warmup'},ca=ca)
        if code!=200:raise RuntimeError(f'endpoint {base}: {code}')
    rows=[]
    for size in sizes:
        payload='X'*size
        for label,base in (('HTTP',http),('HTTPS',https)):
            times=[]
            start=time.perf_counter()
            for _ in range(n):
                tick=time.perf_counter()
                code, data=send_request(base,'/echo-http',{'msg':payload},ca=ca)
                if code!=200 or data.get('echo')!=payload:
                    raise RuntimeError(f'{label} payload verification failed')
                times.append((time.perf_counter()-tick)*1000)
            duration=time.perf_counter()-start
            rows.append({'transport':label,'payload_bytes':size,'requests':n,
                         'median_ms':round(statistics.median(times),4),
                         'p95_ms':round(percentile(times,.95),4),
                         'mean_ms':round(statistics.mean(times),4),
                         'requests_per_second':round(n/duration,2)})
    out=pathlib.Path(output);out.mkdir(parents=True,exist_ok=True)
    info={'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'python':platform.python_version(),'os':platform.platform(),
          'topology':'local loopback; separate HTTP/HTTPS listeners, not Docker',
          'methodology':'new connection per request (TLS handshake included), sequential requests, no auth, verified CA, per-request response equality',
          'rows':rows}
    (out/'results.json').write_text(json.dumps(info,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    with (out/'results.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    lines=['# HTTP проти HTTPS: виміри', '',
           'Дата UTC: '+info['timestamp_utc'],
           'Python: '+info['python'], 'ОС: '+info['os'],
           'Топологія: '+info['topology'],
           'Методика: '+info['methodology'],'',
           '| Протокол | Дані (байти) | Запитів | Медіана, мс | P95, мс | Запитів/с |',
           '|---|---:|---:|---:|---:|---:|']
    for r in rows:
        lines.append(f"| {r['transport']} | {r['payload_bytes']} | {r['requests']} | {r['median_ms']:.4f} | {r['p95_ms']:.4f} | {r['requests_per_second']:.2f} |")
    lines += ['', 'Застереження: час містить створення TCP-з’єднання і TLS handshake; це не лише вартість криптографії. Значення залежать від платформи.']
    (out/'results.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return rows


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--n',type=int,default=20)
    p.add_argument('--sizes',type=int,nargs='+',default=[16,1024,2048])
    p.add_argument('--http-url',default=DEFAULT_HTTP)
    p.add_argument('--https-url',default=DEFAULT_HTTPS)
    p.add_argument('--ca',default=DEFAULT_CA)
    p.add_argument('--out',default='benchmarks')
    a=p.parse_args()
    rows=run(a.n,a.sizes,a.http_url,a.https_url,a.ca,a.out)
    for r in rows:
        print(f"{r['transport']} {r['payload_bytes']} B: p50={r['median_ms']} ms, p95={r['p95_ms']} ms, req/s={r['requests_per_second']}")
    print('Recorded',len(rows),'sets: results.csv, results.json, results.md')

if __name__=='__main__':
    main()
