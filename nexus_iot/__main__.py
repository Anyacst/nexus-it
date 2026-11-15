"""Command-line entry point for the NEXUS-IoT local application."""
from __future__ import annotations
import argparse
from pathlib import Path
from .pipeline import analyze, verify_manifest
from .evaluate import run
from .web import serve

def main() -> int:
    p=argparse.ArgumentParser(prog="nexus-iot",description="Local reconstruction of IoT incidents from supplied forensic evidence")
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("analyze",help="analyze supplied JSONL, PCAP, or PCAPNG files")
    a.add_argument("evidence",type=Path);a.add_argument("--out",type=Path,default=Path("derived/case"));a.add_argument("--tolerance",type=float,default=.05)
    a.add_argument("--max-clock-drift-ppm",type=float,default=1000.0);a.add_argument("--max-clock-residual",type=float,default=2.0)
    a.add_argument("--signing-key",type=Path,help="external 32+ byte secret used to HMAC-sign the evidence manifest")
    v=sub.add_parser("verify-manifest",help="verify a detached evidence manifest HMAC signature")
    v.add_argument("manifest",type=Path);v.add_argument("signature",type=Path);v.add_argument("--key",required=True,type=Path)
    e=sub.add_parser("evaluate",help="regenerate synthetic E1-E7 evidence and run the benchmark")
    e.add_argument("--root",type=Path,default=Path.cwd())
    e.add_argument("--regenerate",action="store_true",help="replace a verified generated dataset after a generator-version change")
    w=sub.add_parser("serve",help="start the local browser interface on loopback only")
    w.add_argument("--host",default="127.0.0.1",choices=["127.0.0.1","localhost"]);w.add_argument("--port",type=int,default=8765)
    args=p.parse_args()
    if args.command=="analyze":
        result=analyze(args.evidence,args.out,args.tolerance,True,args.max_clock_drift_ppm,args.max_clock_residual,args.signing_key)
        print(f"Analyzed {len(result['evidence_manifest'])} evidence files; {len(result['timeline'])} timeline rows.")
        print(f"Markdown report: {args.out.resolve()/'report.md'}")
        if args.signing_key: print(f"Signed manifest: {args.out.resolve()/'evidence_manifest.sig'}")
    elif args.command=="verify-manifest":
        valid=verify_manifest(args.manifest,args.signature,args.key)
        print("Manifest signature valid." if valid else "Manifest signature INVALID.")
        return 0 if valid else 1
    elif args.command=="evaluate":
        results=run(args.root.resolve(),regenerate=args.regenerate)
        for r in results: print(f"{r['condition']} {r['scenario']}: event F1={r['event_f1']:.1%}, timing_within_1s={r['timing_within_tolerance']:.1%}, completeness={r['evidence_completeness']:.1%}")
        print(f"Metrics: {(args.root.resolve()/'derived'/'evaluation'/'metrics.md')}")
    else: serve(args.host,args.port,Path.cwd())
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except (ValueError,FileNotFoundError,PermissionError) as e:
        print(f"error: {e}");raise SystemExit(2)
