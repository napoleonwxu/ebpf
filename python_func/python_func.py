import sys
from bcc import BPF, USDT

if len(sys.argv) < 2:
    print("Usage: %s <tracee_pid>" % sys.argv[0])
    sys.exit(1)

u = USDT(pid=int(sys.argv[1]))
u.enable_probe(probe="function__entry", fn_name="print_functions")
b = BPF(src_file="python_func.c", usdt_contexts=[u])


def print_event(data):
    event = b["events"].event(data)
    print("%-9s %-6d %s" % (event.filename, event.lineno, event.funcname))


# 打印头
print("%-9s %-6s %s" % ("FILE_NAME", "LINE_NUMBER", "FUNC_NAME"))

# 绑定性能事件映射和输出函数，并从映射中循环读取数据
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
