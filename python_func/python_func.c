#include <uapi/linux/ptrace.h>

// 定义数据结构和性能事件映射
struct data_t {
    char filename[128];
    char funcname[64];
    int lineno;
};
BPF_PERF_OUTPUT(events);

int print_functions(struct pt_regs *ctx)
{
    uint64_t argptr;
    struct data_t data = { };

    // 参数1是文件名
    bpf_usdt_readarg(1, ctx, &argptr);
    bpf_probe_read_user(&data.filename, sizeof(data.filename), (void *)argptr);

    // 参数2是函数名
    bpf_usdt_readarg(2, ctx, &argptr);
    bpf_probe_read_user(&data.funcname, sizeof(data.funcname), (void *)argptr);

    // 参数3是行号
    bpf_usdt_readarg(3, ctx, &data.lineno);

    // 最后提交性能事件
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
