from bcc import BPF

# 1) load BPF program
b = BPF(src_file="trace-open.c")
b.attach_kprobe(event="do_sys_openat2", fn_name="hello_world")

# 2) print header
print("%-18s %-16s %-6s %-16s" % ("TIME(s)", "PNAME", "PID", "FILE"))

# 3) define the callback for perf event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events2"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %-16s" % (time_s, event.comm, event.pid, event.fname))

# 4) loop with callback to print_event
# 在 BCC 中，与 eBPF 程序中 BPF_PERF_OUTPUT  相对应的用户态辅助函数是 open_perf_buffer(),
# 它需要传入一个回调函数，用于处理从 Perf 事件类型的 BPF 映射中读取到的数据。
b["events2"].open_perf_buffer(print_event)
while 1:
    try:
        # perf_buffer_poll 读取映射的内容
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
