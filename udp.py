#!/usr/bin/python

from bcc import BPF

device = "int0"
b = BPF(src_file="udp.c")
fn = b.load_func("udp_reverse", BPF.XDP)
b.attach_xdp(device, fn, 0)

try:
    b.trace_print()
except KeyboardInterrupt:
    pass

b.remove_xdp(device, 0)