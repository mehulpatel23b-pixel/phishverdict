"""Command-line interface for phishverdict."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, engine

EXIT_ERR = 2
USAGE = 64
BANNER = "phishverdict v{} - offline URL triage (defensive analysis only)".format(__version__)


def _collect_urls(args):
    """URLs may come as CLI args, files, or '-' for stdin, one per line."""
    urls = []
    for source in args.sources:
        if source == "-":
            urls.extend(l.strip() for l in sys.stdin if l.strip())
        elif source.startswith(("http://", "https://", "ftp://",
                                "javascript:", "data:")) or "/" not in source:
            urls.append(source)
        else:
            try:
                with open(source, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            urls.append(line)
            except OSError as e:
                print(f"phishverdict: cannot read {source}: {e}", file=sys.stderr)
                return None
    return urls


def _render_text(results, summary):
    out = []
    for r in results:
        out.append("─" * 64)
        out.append(f"URL      : {r.url}")
        out.append(f"host     : {r.host or '-'}"
                   + (f"   (registrable: {r.registrable})" if r.registrable else ""))
        out.append(f"VERDICT  : {r.verdict}{' ' + str(r.score) if r.score else ''}")
        for h in r.hits:
            out.append(f"  [!] {h.signal_id} ({h.weight:>2}) {h.title}: {h.detail}")
        if not r.hits:
            out.append("  [ok] no triage signals raised")
    out.append("─" * 64)
    out.append("summary  : " + "  ".join(
        f"{k}:{v}" for k, v in summary.items()))
    out.append("exit      : "
               + ("flagged" if summary["SUSPICIOUS"] + summary["CRITICAL"] else "clear"))
    out.append("phishverdict is a heuristic triage aid, not a verdict. "
               "Use it defensively, on URLs you are authorized to analyze.")
    return "\n".join(out)


def _render_json(results, summary):
    doc = {
        "version": __version__,
        "results": [{
            "url": r.url, "host": r.host, "registrable": r.registrable,
            "scheme": r.scheme, "score": r.score, "verdict": r.verdict,
            "signals": [{"id": h.signal_id, "weight": h.weight,
                         "title": h.title, "detail": h.detail} for h in r.hits],
        } for r in results],
        "summary": summary,
    }
    return json.dumps(doc, indent=2)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="phishverdict",
        description=BANNER,
        epilog="analyze URLs you receive in a defensive/authorized context only")
    p.add_argument("sources", nargs="*", metavar="URL|FILE|-",
                   help="URLs, files of URLs (one per line, # comments ok), or '-' for stdin")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--version", action="version", version="phishverdict " + __version__)
    args = p.parse_args(argv)

    if not args.sources:
        p.print_usage(sys.stderr)
        print("phishverdict: give me URLs, a file of URLs, or '-' for stdin",
              file=sys.stderr)
        return USAGE

    urls = _collect_urls(args)
    if urls is None:
        return EXIT_ERR
    if not urls:
        print("phishverdict: no URLs to analyze", file=sys.stderr)
        return EXIT_ERR

    results, summary = engine.triage(urls)
    if args.json:
        print(_render_json(results, summary))
    else:
        print(_render_text(results, summary))
    flagged = summary["SUSPICIOUS"] + summary["CRITICAL"]
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
