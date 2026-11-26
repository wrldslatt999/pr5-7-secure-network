"""Filter JSONL security audit events by user, event type and UTC timestamp."""
import argparse
import collections
import datetime
import json
import pathlib


def parse_date(value):
    parsed=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return parsed


def collect(path,user=None,event=None,since=None,until=None):
    result=[]
    for raw in pathlib.Path(path).read_text(encoding='utf-8').splitlines():
        try:
            item=json.loads(raw)
            date=parse_date(item['timestamp'])
        except (ValueError,KeyError,json.JSONDecodeError):
            continue
        if user and item.get('user')!=user:continue
        if event and item.get('event')!=event:continue
        if since and date<since:continue
        if until and date>until:continue
        result.append(item)
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--file',default='runtime/events.jsonl')
    p.add_argument('--user');p.add_argument('--event');p.add_argument('--since');p.add_argument('--until')
    p.add_argument('--show',type=int,default=5)
    a=p.parse_args()
    events=collect(a.file,a.user,a.event,parse_date(a.since) if a.since else None,parse_date(a.until) if a.until else None)
    print('Filtered events:',len(events))
    print('By type:',dict(collections.Counter(x['event'] for x in events)))
    print('By status:',dict(collections.Counter(x['status'] for x in events if 'status' in x)))
    for item in events[-max(a.show,0):]:
        print(json.dumps(item,ensure_ascii=False))

if __name__=='__main__':main()
