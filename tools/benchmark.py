#!/usr/bin/env python3
"""
benchmark.py - how fast do the rules run, and which rule or regex costs the most?

Correctness is proven elsewhere; this measures cost, so a rule that is right but slow
(a regex that backtracks on long command lines, a list of hundreds of values) is
visible before it reaches a SIEM that bills by compute or times out a scheduled search.

It replays every detection over a log export - or over a synthetic one generated from
the replay corpus and every test event, at any size - exactly as `rasd replay` routes
events, and reports:

  throughput        events per second through routing + matching with compiled rules, as
                    replay and evidence run them (best of --repeat runs); --compare also
                    times the reference interpreter and checks it raises the same alerts
  per rule          total time, microseconds per routed event, alerts
  per regex         time of every |re pattern over the values it reads, slowest first
  correlations      events per second through every correlation detection (base rule,
                    grouping, windows, distinct counts) over the same events - in memory mode
  memory            peak resident memory of the process
  alerts            alerts generated

Two modes
  in memory   (default up to 250,000 events) every event is held in a list; throughput is
              the best of --repeat passes and the rule / regex tables cover every event
  --stream    events are generated or read line by line and processed in chunks of
              --chunk-size, so memory stays flat at any size; one pass, and the rule /
              regex tables are measured on the first --sample events of every chunk.
              Chosen automatically above 250,000 generated events or 100 MB of exports.

Usage
  python tools/benchmark.py --generate 100000
  python tools/benchmark.py big-export.jsonl --profile elastic-ecs --top 10
  python tools/benchmark.py --generate 1000000 --stream --chunk-size 50000
  python tools/benchmark.py --generate 5000000 --stream --write-sample samples/big.jsonl --json benchmark.json
  python tools/benchmark.py --generate 20000 --min-eps 2000          # fail below 2000 events/s
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import os
import random
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, ROOT, load_detections, load_jsonl  # noqa: E402
from convert import logsource_key  # noqa: E402
import profiles  # noqa: E402
from replay import route  # noqa: E402
from sigma_engine import RE_FLAGS, SigmaError, _get_field, compile_rule, matches  # noqa: E402

CORPUS = ROOT / "samples" / "replay" / "lab-day.jsonl"
HOSTS = [f"WS{n:03d}.corp.lab" for n in range(1, 201)] + ["DC01.corp.lab", "DC02.corp.lab", "FS01.corp.lab"]
NOISE = ("--profile-directory=Default", "/quiet /norestart", "-NoLogo", "--type=renderer --lang=en-US",
         "/S /D=C:\\Program Files\\App", "-ExecutionPolicy RemoteSigned -File C:\\Scripts\\inventory.ps1")


def peak_rss_mb() -> float | None:
    try:
        import resource
    except ImportError:                       # Windows
        return None
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(rss / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)


STREAM_ABOVE_EVENTS = 250_000
STREAM_ABOVE_BYTES = 100 * 1024 * 1024
RESERVOIR = 20_000                           # values kept per regex field in --stream mode


def iter_generated(n: int, dets, seed: int = 7):
    """A synthetic export, one event at a time: replay-corpus events with new hosts, times and
    command-line noise, with every true positive and true negative mixed in at about 1 %."""
    rnd = random.Random(seed)
    base = load_jsonl(CORPUS) if CORPUS.exists() else []
    attacks = []
    for d in dets:
        for kind in ("true_positive", "true_negative"):
            for ev in d.tests(kind):
                ev = {k: v for k, v in ev.items() if not k.startswith("_")}
                if route(ev) is None:          # test events carry no channel: give them the rule's own
                    ev.setdefault("Channel", {"process_creation": "Microsoft-Windows-Sysmon/Operational",
                                              "process_access": "Microsoft-Windows-Sysmon/Operational",
                                              "registry_set": "Microsoft-Windows-Sysmon/Operational",
                                              "windows/security": "Security",
                                              "windows/system": "System"}[logsource_key(d.rule)])
                attacks.append(ev)
    pool = base or attacks
    start = datetime(2026, 10, 1)
    for i in range(n):
        src = rnd.choice(attacks) if attacks and rnd.random() < 0.01 else rnd.choice(pool)
        ev = copy.copy(src)
        ev["UtcTime"] = (start + timedelta(milliseconds=i * 250)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        ev["Computer"] = rnd.choice(HOSTS)
        if isinstance(ev.get("CommandLine"), str) and rnd.random() < 0.5:
            ev["CommandLine"] = f"{ev['CommandLine']} {rnd.choice(NOISE)}"
        yield ev


def generate(n: int, dets, seed: int = 7) -> list[dict]:
    return list(iter_generated(n, dets, seed))


def iter_files(paths: list[str], profile: str | None):
    """Events of JSONL exports read line by line, normalised with a profile. 'auto' decides
    on the first 500 events. Returns (iterator, profile used)."""
    def lines():
        for p in paths:
            with open(p, encoding="utf-8-sig") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)
    raw = lines()
    head = list(itertools.islice(raw, 500))
    name = profiles.detect(head)[0] if profile == "auto" else profile
    prof = profiles.load(name)
    events = itertools.chain(head, raw)
    return ((profiles.normalize(e, prof) for e in events) if prof else events), (name or profiles.NATIVE)


def chunked(events, size: int):
    it = iter(events)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            return
        yield chunk


def compile_sources(dets) -> dict:
    by_source = defaultdict(list)
    for d in dets:
        try:
            by_source[logsource_key(d.rule)].append((d, compile_rule(d.rule)))
        except SigmaError as e:
            print(f"{RED}{d.id}: {e}{RESET}")
    return by_source


def run_once(events, by_source, compiled: bool = True) -> tuple[float, int]:
    """Routing + matching over every event; compiled rules (as replay and evidence use them)
    or the reference interpreter matches()."""
    t0 = time.perf_counter()
    alerts = 0
    for ev in events:
        for d, fn in by_source.get(route(ev), ()):
            alerts += fn(ev) if compiled else matches(d.rule, ev)
    return time.perf_counter() - t0, alerts


def per_rule(events, by_source) -> dict[str, dict]:
    stats = defaultdict(lambda: {"seconds": 0.0, "events": 0, "alerts": 0})
    for ev in events:
        for d, fn in by_source.get(route(ev), ()):
            t0 = time.perf_counter()
            hit = fn(ev)
            s = stats[d.id]
            s["seconds"] += time.perf_counter() - t0
            s["events"] += 1
            s["alerts"] += hit
    return stats


def regexes(dets) -> list[tuple[str, str, str, int]]:
    """(detection, field, pattern, flags) for every |re value in every rule."""
    out = []
    for d in dets:
        def walk(sel):
            if isinstance(sel, dict):
                for key, value in sel.items():
                    field, *mods = key.split("|")
                    if "re" in mods:
                        flags = sum(RE_FLAGS[m] for m in set(mods) & RE_FLAGS.keys())
                        for v in value if isinstance(value, list) else [value]:
                            out.append((d.id, field, str(v), flags))
            elif isinstance(sel, list):
                for s in sel:
                    walk(s)
        for name, sel in d.rule["detection"].items():
            if name != "condition":
                walk(sel)
    return out


def per_regex(events, dets) -> list[dict]:
    routed = defaultdict(list)
    for ev in events:
        routed[route(ev)].append(ev)
    by_key = {}
    for d in dets:
        src = logsource_key(d.rule)
        for det_id, field, _p, _f in regexes([d]):
            if (src, field) not in by_key:
                by_key[(src, field)] = [str(v) for v in (_get_field(ev, field) for ev in routed.get(src, []))
                                        if v not in (None, "")]
    return regex_rows(by_key, dets)


def regex_rows(values_by_key: dict, dets) -> list[dict]:
    by_id = {d.id: logsource_key(d.rule) for d in dets}
    rows = []
    for det_id, field, pattern, flags in regexes(dets):
        values = values_by_key.get((by_id[det_id], field), [])
        rx = re.compile(pattern, flags)
        t0 = time.perf_counter()
        for v in values:
            rx.search(v)
        secs = time.perf_counter() - t0
        rows.append({"detection": det_id, "field": field, "pattern": pattern, "values": len(values),
                     "seconds": round(secs, 6), "us_per_value": round(1e6 * secs / len(values), 3) if values else 0.0})
    return sorted(rows, key=lambda r: -r["us_per_value"])


def stream(events, dets, chunk_size: int = 50_000, sample: int = 2_000, compare: bool = False,
           writer=None) -> dict:
    """One pass in chunks: memory is bounded by the chunk, not by the export.
    Throughput times routing + matching only; rule and regex costs come from the first
    `sample` events of every chunk (regex values through a reservoir of RESERVOIR each)."""
    by_source = compile_sources(dets)
    needed = defaultdict(set)                      # log source -> fields read by some regex
    by_id = {d.id: logsource_key(d.rule) for d in dets}
    for det_id, field, _p, _f in regexes(dets):
        needed[by_id[det_id]].add(field)
    rnd = random.Random(1)
    reservoir, seen = defaultdict(list), defaultdict(int)
    stats = defaultdict(lambda: {"seconds": 0.0, "events": 0, "alerts": 0})
    routed_by = defaultdict(int)
    total = alerts = chunks = sampled = 0
    match = interp = 0.0
    wall0 = time.perf_counter()
    for chunk in chunked(events, chunk_size):
        chunks += 1
        if writer:
            writer.write("".join(json.dumps(e) + "\n" for e in chunk))
        t0 = time.perf_counter()
        for ev in chunk:
            src = route(ev)
            rules = by_source.get(src)
            if rules:
                routed_by[src] += 1
                for _d, fn in rules:
                    alerts += fn(ev)
        match += time.perf_counter() - t0
        total += len(chunk)
        for ev in chunk[:sample]:
            sampled += 1
            src = route(ev)
            for d, fn in by_source.get(src, ()):
                t1 = time.perf_counter()
                hit = fn(ev)
                st = stats[d.id]
                st["seconds"] += time.perf_counter() - t1
                st["events"] += 1
                st["alerts"] += hit
                if compare:
                    t2 = time.perf_counter()
                    ref = matches(d.rule, ev)
                    interp += time.perf_counter() - t2
                    if ref != hit:
                        raise SystemExit(f"compiled and interpreted engines disagree on {d.id}: {json.dumps(ev)[:200]}")
            for field in needed.get(src, ()):
                v = _get_field(ev, field)
                if v in (None, ""):
                    continue
                key = (src, field)
                seen[key] += 1
                bucket = reservoir[key]
                if len(bucket) < RESERVOIR:
                    bucket.append(str(v))
                else:
                    j = rnd.randrange(seen[key])
                    if j < RESERVOIR:
                        bucket[j] = str(v)
    wall = time.perf_counter() - wall0
    rows = []
    for d in dets:
        st = stats.get(d.id)
        if not st:
            continue
        per = st["seconds"] / st["events"] if st["events"] else 0.0
        rows.append({"detection": d.id, "seconds": round(per * routed_by[by_id[d.id]], 4), "events": routed_by[by_id[d.id]],
                     "alerts": st["alerts"], "us_per_event": round(1e6 * per, 2), "sampled_events": st["events"]})
    sampled_rule_secs = sum(st["seconds"] for st in stats.values())
    return {
        "mode": "stream", "events": total, "routed": sum(routed_by.values()), "detections": len(dets),
        "chunks": chunks, "chunk_size": chunk_size, "sampled_events": sampled,
        "seconds": round(match, 4), "events_per_second": round(total / match) if match else None,
        "end_to_end_seconds": round(wall, 4),
        "end_to_end_events_per_second": round(total / wall) if wall else None,
        "alerts": alerts,
        "interpreted": ({"sampled_events": sampled, "slower_by": round(interp / sampled_rule_secs, 1)}
                        if compare and sampled_rule_secs else None),
        "rules": sorted(rows, key=lambda r: -r["seconds"]),
        "regexes": regex_rows(reservoir, dets),
        "peak_rss_mb": peak_rss_mb(),
    }


def correlation_throughput(events: list[dict], corrs, repeat: int = 3) -> dict | None:
    """Every correlation over all events, as replay and evidence run them: best of `repeat`."""
    if not corrs:
        return None
    from correlation import evaluate                     # imported here: correlation imports replay
    fns = {c.id: compile_rule(c.base) for c in corrs}
    best, alerts = None, 0
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        alerts = sum(len(evaluate(c, events, base_fn=fns[c.id])) for c in corrs)
        secs = time.perf_counter() - t0
        best = secs if best is None else min(best, secs)
    return {"correlations": len(corrs), "seconds": round(best, 4),
            "events_per_second": round(len(events) / best) if best else None, "alerts": alerts}


def benchmark(events: list[dict], dets, repeat: int = 3, compare: bool = False, corrs=()) -> dict:
    by_source = compile_sources(dets)
    routed = sum(1 for ev in events if route(ev))
    runs = [run_once(events, by_source) for _ in range(max(1, repeat))]
    best = min(r[0] for r in runs)
    rules = per_rule(events, by_source)
    interpreted = None
    if compare:
        secs, alerts = run_once(events, by_source, compiled=False)
        if alerts != runs[0][1]:
            raise SystemExit(f"compiled and interpreted engines disagree: {runs[0][1]} vs {alerts} alerts")
        interpreted = {"seconds": round(secs, 4), "events_per_second": round(len(events) / secs) if secs else None}
    return {
        "mode": "memory", "events": len(events), "routed": routed, "detections": len(dets), "repeat": max(1, repeat),
        "seconds": round(best, 4), "events_per_second": round(len(events) / best) if best else None,
        "alerts": runs[0][1], "interpreted": interpreted,
        "rules": sorted(({"detection": k, "seconds": round(v["seconds"], 4), "events": v["events"], "alerts": v["alerts"],
                          "us_per_event": round(1e6 * v["seconds"] / v["events"], 2) if v["events"] else 0.0}
                         for k, v in rules.items()), key=lambda r: -r["seconds"]),
        "regexes": per_regex(events, dets),
        "correlations": correlation_throughput(events, corrs, repeat),
        "peak_rss_mb": peak_rss_mb(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="*", help="JSONL exports to benchmark on")
    ap.add_argument("--generate", type=int, metavar="N", help="benchmark on N synthetic events instead")
    ap.add_argument("--profile", help="telemetry profile from mappings/ (or 'auto') the logs are written in")
    ap.add_argument("--filter", help="only detections matching this text")
    ap.add_argument("--repeat", type=int, default=3, help="throughput runs; the best one counts (default 3)")
    ap.add_argument("--top", type=int, default=5, help="rows in the rule and regex tables (default 5)")
    ap.add_argument("--write-sample", metavar="PATH", help="also save the generated events as JSONL")
    ap.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    ap.add_argument("--min-eps", type=float, help="fail when throughput is below this many events per second")
    ap.add_argument("--compare", action="store_true",
                    help="also time the reference interpreter matches() and check it raises the same alerts")
    ap.add_argument("--stream", action="store_true",
                    help=f"process in chunks with flat memory (automatic above {STREAM_ABOVE_EVENTS:,} generated events "
                         "or 100 MB of exports)")
    ap.add_argument("--chunk-size", type=int, default=50_000, help="events per chunk in --stream mode (default 50000)")
    ap.add_argument("--sample", type=int, default=2_000,
                    help="events per chunk timed rule by rule in --stream mode (default 2000)")
    args = ap.parse_args()
    if not args.logs and not args.generate:
        ap.error("give JSONL exports or --generate N")

    dets = load_detections(args.filter)
    size = sum(os.path.getsize(p) for p in args.logs) if args.logs else 0
    streaming = args.stream or (args.generate or 0) > STREAM_ABOVE_EVENTS or size > STREAM_ABOVE_BYTES
    src = f"{args.generate} synthetic events" if args.generate else " + ".join(args.logs)
    if streaming:
        if args.generate:
            events, used = iter_generated(args.generate, dets), profiles.NATIVE
        else:
            events, used = iter_files(args.logs, args.profile)
        writer = open(args.write_sample, "w", encoding="utf-8") if args.write_sample and args.generate else None
        try:
            res = stream(events, dets, max(1, args.chunk_size), max(0, args.sample), args.compare, writer)
        finally:
            if writer:
                writer.close()
        res["profile"] = used
    else:
        t0 = time.perf_counter()
        if args.generate:
            events, used = generate(args.generate, dets), profiles.NATIVE
            if args.write_sample:
                Path(args.write_sample).write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
        else:
            events, used = profiles.apply([e for p in args.logs for e in load_jsonl(Path(p))], args.profile)
        prepare = time.perf_counter() - t0
        from correlation import load_correlations       # imported here: correlation imports replay
        res = benchmark(events, dets, args.repeat, args.compare, load_correlations(args.filter))
        res["prepare_seconds"], res["profile"] = round(prepare, 3), used

    print(f"{BOLD}RASD benchmark · {src} · profile {used} · {res['mode']} mode{RESET}\n")
    print(f"  events            {res['events']} ({res['routed']} routed to a rule's log source)")
    if res["mode"] == "stream":
        print(f"  throughput        {GREEN}{res['events_per_second']} events/s{RESET} "
              f"{DIM}(routing + matching: {res['seconds']} s for {res['detections']} detections){RESET}")
        print(f"  end to end        {res['end_to_end_events_per_second']} events/s "
              f"{DIM}({res['end_to_end_seconds']} s including {'generation' if args.generate else 'reading and parsing'}, "
              f"sampling{' and the interpreter check' if args.compare else ''}; "
              f"{res['chunks']} chunks of {res['chunk_size']}){RESET}")
        if res["interpreted"]:
            print(f"  interpreter       {res['interpreted']['slower_by']}x slower than compiled "
                  f"{DIM}(matches(), same verdicts on {res['interpreted']['sampled_events']} sampled events){RESET}")
    else:
        print(f"  throughput        {GREEN}{res['events_per_second']} events/s{RESET} "
              f"{DIM}(best of {res['repeat']}: {res['seconds']} s for {res['detections']} detections){RESET}")
        if res["interpreted"]:
            print(f"  interpreter       {res['interpreted']['events_per_second']} events/s {DIM}(matches(), same alerts; "
                  f"{res['events_per_second'] / max(res['interpreted']['events_per_second'], 1):.1f}x slower){RESET}")
        if res.get("correlations"):
            c = res["correlations"]
            print(f"  correlations      {GREEN}{c['events_per_second']} events/s{RESET} {DIM}({c['correlations']} correlations: "
                  f"base rule, grouping, windows and distinct counts in {c['seconds']} s; {c['alerts']} alerts){RESET}")
        print(f"  load / generate   {res['prepare_seconds']} s")
    print(f"  peak memory       {res['peak_rss_mb']} MB" if res["peak_rss_mb"] is not None else "  peak memory       n/a")
    print(f"  alerts            {res['alerts']}\n")
    sampled = f" (timed on {res['sampled_events']} sampled events)" if res["mode"] == "stream" else ""
    print(f"{BOLD}  Slowest rules{sampled}{RESET}")
    for r in res["rules"][: args.top]:
        print(f"    {r['detection']:<48} {r['seconds']:>8.3f} s  {r['us_per_event']:>8.2f} µs/event  {r['alerts']} alerts")
    print(f"\n{BOLD}  Slowest regexes{RESET}")
    for r in res["regexes"][: args.top]:
        print(f"    {r['detection']:<48} {r['field']:<12} {r['us_per_value']:>7.3f} µs/value  {DIM}{r['pattern'][:60]}{RESET}")
    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    if args.min_eps and (res["events_per_second"] or 0) < args.min_eps:
        print(f"\n{RED}throughput {res['events_per_second']} events/s is below --min-eps {args.min_eps:g}{RESET}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
