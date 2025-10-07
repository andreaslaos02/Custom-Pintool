#!/usr/bin/env python3
# annotate_trace.py
# Usage:
#   python3 annotate_trace.py pintool.log pinatrace.out pinatrace.annotated.out
#
# - Παίρνει ALLOC γραμμές από pintool.log (στην μορφή που παράγει
#   το εργαλείο σου: "[ALLOC] p=0xADDR size=N tag=TAG @file:line (func)")
# - Φτιάχνει sorted list ranges (start, end, tag, size, site)
# - Διαβάζει pinatrace.out (μορφή: "<ip>: R|W <addr> <tag_or_->")
# - Αν addr εμπίπτει σε κάποιο range, προσθέτει ",<tag>,<size>,<site>"
# - Εξάγει αποτέλεσμα σε pinatrace.annotated.out
#
# Αυτό το script χρησιμοποιεί binary-search στα starts για αποδοτικότητα.


#chmod +x annotate_trace.py
#python3 annotate_trace.py pintool.log pinatrace.out pinatrace.annotated.out

import sys, re, bisect

if len(sys.argv) != 4:
    print("Usage: python3 annotate_trace.py pintool.log pinatrace.out out.annot", file=sys.stderr)
    sys.exit(2)

plog = sys.argv[1]
trace = sys.argv[2]
outf = sys.argv[3]

# regex για γραμμές ALLOC (προσαρμόσιμο αν έχεις διαφορετικό format)
# παράδειγμα γραμμής:
# [ALLOC] p=0x16e16b0 size=16 tag=Node @ds_demo.c:23 (make_node)
alloc_re = re.compile(r'^\[ALLOC\]\s+p=(0x[0-9a-fA-F]+)\s+size=(\d+)\s+tag=([^\s]+)\s+@([^:]+:\d+)\s+\(([^)]+)\)')

ranges = []   # list of tuples (start_int, end_int, tag, size, site)
starts = []   # list of start_int for bisect

with open(plog, 'r') as f:
    for line in f:
        m = alloc_re.search(line)
        if not m:
            continue
        addr_s = m.group(1)
        size_s = m.group(2)
        tag = m.group(3)
        site = m.group(4) + " (" + m.group(5) + ")"
        start = int(addr_s, 16)
        size = int(size_s)
        end = start + size
        ranges.append((start, end, tag, size, site))

# sort by start
ranges.sort(key=lambda x: x[0])
starts = [r[0] for r in ranges]

def find_range(addr):
    # find rightmost range with start <= addr, then check if addr < end
    i = bisect.bisect_right(starts, addr)
    if i == 0:
        return None
    r = ranges[i-1]
    if addr < r[1]:
        return r
    return None

# parse pinatrace lines: "<ip>: R|W <addr> <tag_or_->"
trace_line_re = re.compile(r'^(\S+):\s+([RW])\s+(0x[0-9a-fA-F]+)(?:\s+(\S+))?')

with open(trace, 'r') as fin, open(outf, 'w') as fout:
    for line in fin:
        m = trace_line_re.match(line)
        if not m:
            fout.write(line)  # passthrough if different format
            continue
        ip = m.group(1)
        rw = m.group(2)
        addr = int(m.group(3), 16)
        current_tag = m.group(4) if m.group(4) else "-"
        r = find_range(addr)
        if r:
            # r = (start,end,tag,size,site)
            tag = r[2]
            size = r[3]
            site = r[4]
            fout.write(f"{ip}: {rw} 0x{addr:x} {tag} size={size} site=\"{site}\"\n")
        else:
            fout.write(line)
print("Wrote", outf, " (ranges indexed:", len(ranges), ")\n", file=sys.stderr)