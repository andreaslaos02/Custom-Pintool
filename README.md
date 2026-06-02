Custom PIN Tool — Memory Trace for Heterogeneous Memory Research
A multithreaded Intel PIN tool (pinatrace_alloc_mt) designed to record the memory access patterns of Memcached 1.6.14. Developed as part of a diploma thesis on caching strategies for heterogeneous memory systems (DRAM + NVM/PCM).

Overview
This tool instruments a running Memcached process and produces a unified memory trace that captures:

Heap allocations and frees — malloc, calloc, realloc, reallocarray, aligned_alloc, memalign, valloc, pvalloc, posix_memalign, strdup, strndup, mmap, munmap, mremap, and their glibc aliases.
Load/store memory accesses — recorded per instruction, attributed to their containing heap region, stack region, or global image section.
Source-level metadata — each allocation is tagged with its call site (file, line, function) via addr2line, with caching to avoid redundant lookups.
Thread roles — Memcached worker threads are identified and labeled separately from internal/other threads.

The output trace is then used as input to the DineroIV cache simulator to study Write-Through vs. Write-Back caching policies under a DRAM-as-cache / NVM-as-main-memory architecture.

Output Files
FileDescriptionpinatrace.outUnified trace: ALLOC/FREE events + load/store accessespintool.logDiagnostic log: thread lifecycle, hooks installed, pending alloc state at exit
Trace Format
ALLOC <addr> <size> <tag> <file>:<line> [caller_ip]
FREE  <addr> <tag>
R <addr> <size> <region_tag> <src_file>:<line>
W <addr> <size> <region_tag> <src_file>:<line>
FREE-UNKNOWN <addr>   # mmap-backed allocations not seen by malloc hooks

Knobs (Command-line Options)
KnobDefaultDescription-use_libc_hooks0Also hook malloc/free in libc (in addition to the application's own allocator)-src_debug0Verbose diagnostics for source-location resolution-trace_untracked0Log accesses that fall outside any tracked region-main_exe_only1Restrict load/store tracing to the main executable image-trace_stack1Include accesses to tracked per-thread stack regions-trace_globals1Track accesses to global sections (.data, .bss, .got, etc.)-worker_only0Restrict tracing to threads identified as Memcached worker threads-trace_libc_memops0Include memcpy/memset/strcmp accesses when they touch a tracked heap region

Tracing Window (SIGUSR2)
Load/store recording is off by default to avoid capturing the Memcached startup and load phase.
Send SIGUSR2 to the target process to toggle load/store tracing on or off:
bashkill -USR2 <memcached_pid>
This allows you to trace only the steady-state query phase (e.g., an mcperf benchmark run), keeping the trace clean and focused.

Usage
Build
bash# From the PIN kit root
make PIN_ROOT=/path/to/pin obj-intel64/pinatrace_alloc_mt.so
Run
bash/path/to/pin/pin \
  -t obj-intel64/pinatrace_alloc_mt.so \
  -main_exe_only 1 \
  -trace_stack 1 \
  -trace_globals 1 \
  -- memcached -m 512 -t 4 &

MEMCACHED_PID=$!

# Start workload (e.g., mcperf)
mcperf -s 127.0.0.1 --loadonly -K 30 -V 200 -i uniform -n 1000000
kill -USR2 $MEMCACHED_PID   # start tracing
mcperf -s 127.0.0.1 -u 0.00 -K 30 -V 200 -i uniform -n 1000000 -t 60
kill -USR2 $MEMCACHED_PID   # stop tracing

kill $MEMCACHED_PID

Design Notes

Thread-local state is managed via a PIN TLS key (g_tls_key) with a per-thread ThreadCtx struct. Each thread has its own pending-alloc state, calloc stack, and role label.
Lock hierarchy: g_regions_lock → g_events_lock → g_stack_lock → g_src_cache_lock → g_img_cache_lock → g_hook_lock. Never acquire in reverse order.
FREE-UNKNOWN entries: Occur when glibc services large allocations directly via mmap (without calling malloc), so the PIN hooks never see the original allocation.
Source location caching: addr2line results are cached by (image_path, image_offset) to avoid repeated subprocess calls on the hot path.
Image-to-IP caching: GetImgFromIpCached avoids calling PIN_LockClient on every load/store by maintaining a separate hash map protected by g_img_cache_lock.
Deduplication of hooked routines: TryMarkHooked (via g_hooked_rtn_addrs) prevents double-instrumentation of aliased symbols (e.g., __GI___malloc vs. malloc).

Requirements

Intel PIN (tested with PIN 3.x, x86-64)
Linux (x86-64), glibc
addr2line in PATH (for source-level tagging)
Memcached 1.6.14 compiled with debug symbols (-g) for accurate source attribution
