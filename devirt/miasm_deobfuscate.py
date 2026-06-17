#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from collections import defaultdict

from miasm.analysis.machine import Machine
from miasm.core.bin_stream import bin_stream_str
from miasm.core.locationdb import LocationDB
from miasm.expression.simplifications import expr_simp

BINARY = Path(__file__).parent.parent.parent / "AuthNative.so"
TRACE = Path(__file__).parent / "state_enter_trace.jsonl"


def va_to_file(va):
    return va - 0x1000 if va >= 0x114000 else va


def load_trace(path):
    trace = []
    with open(path) as f:
        for line in f:
            trace.append(int(json.loads(line)["off"], 16))
    return trace


def get_blocks(trace):
    blocks = []
    start = trace[0]
    prev = trace[0]
    for va in trace[1:]:
        if va - prev > 7:
            blocks.append((start, prev))
            start = va
        prev = va
    blocks.append((start, prev))
    seen = {}
    for s, e in blocks:
        if s not in seen or (e - s) > (seen[s] - s):
            seen[s] = e
    return sorted(seen.items())


def lift_block(machine, binary, block_start, block_end):
    file_off = va_to_file(block_start)
    read_size = min(512, len(binary) - file_off)
    if file_off < 0 or read_size < 16:
        return None
    chunk = bytes(binary[file_off : file_off + read_size])
    if all(b == 0 for b in chunk[:4]):
        return None

    loc_db = LocationDB()
    bs = bin_stream_str(chunk, base_address=block_start)
    try:
        mdis = machine.dis_engine(bs, loc_db=loc_db)
        mdis.follow_call = False
        mdis.dontdis_retcall = True
        block = mdis.dis_block(block_start)
    except Exception:
        return None
    if not block or not block.lines:
        return None

    try:
        lifter = machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg()
        lifter.add_asmblock_to_ircfg(block, ircfg)
    except Exception:
        return None

    ops = []
    for irb_loc in ircfg.blocks:
        irb = ircfg.blocks[irb_loc]
        for assignblk in irb:
            for dst, src in assignblk.items():
                dst_s = str(dst)
                if dst_s in ("zf", "nf", "pf", "cf", "of", "af", "IRDst"):
                    continue
                simplified = expr_simp(src)
                s = str(simplified)
                if s == dst_s:
                    continue
                if len(s) > 300:
                    s = s[:150] + "..."
                ops.append(f"  {dst_s} = {s}")
    return {"va": block_start, "end": block_end, "n_insns": len(block.lines), "ops": ops}


def main():
    binary_path = sys.argv[1] if len(sys.argv) > 1 else str(BINARY)
    trace_path = sys.argv[2] if len(sys.argv) > 2 else str(TRACE)

    binary = bytearray(Path(binary_path).read_bytes())
    trace = load_trace(trace_path)
    blocks = get_blocks(trace)

    machine = Machine("x86_64")
    results = []

    for i, (start, end) in enumerate(blocks):
        r = lift_block(machine, binary, start, end)
        if r and r["ops"]:
            results.append(r)
        if (i + 1) % 20 == 0:
            print(f"  {i+1}/{len(blocks)}...", file=sys.stderr)

    for r in results:
        print(f"// 0x{r['va']:06x}..0x{r['end']:06x} ({r['n_insns']} insns -> {len(r['ops'])} ops)")
        for op in r["ops"]:
            print(op)
        print()


if __name__ == "__main__":
    main()
