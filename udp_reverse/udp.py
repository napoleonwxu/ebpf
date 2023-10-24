#!/usr/bin/python

from bcc import BPF

device = "int0"
# 编译XDP程序
b = BPF(src_file="udp.c")
fn = b.load_func("udp_reverse", BPF.XDP)
# 加载XDP程序到网卡
b.attach_xdp(device, fn, 0)

try:
    b.trace_print()
except KeyboardInterrupt:
    pass

# 卸载XDP程序
b.remove_xdp(device, 0)