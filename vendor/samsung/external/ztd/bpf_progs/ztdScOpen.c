
#include "bpf_shared.h"
#include <ztd_sc_shared.h>

#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(sc_open_data_map, HASH, uint64_t, sc_open_data_t, 128, AID_SYSTEM);
DEFINE_BPF_SHARED_MAP_GRW(sc_tracer_map, ARRAY, uint32_t, sc_tracer_t, 1, AID_SYSTEM);

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(sc_data_ringbuf, sc_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", true,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, false, false, false);
#endif

static inline __always_inline void onSyscallOpenEnter(sys_enter_data_t *args) {
    unsigned long long event_time = bpf_ktime_get_boot_ns();
    unsigned long long uid_gid = bpf_get_current_uid_gid();

    sc_tracer_t *sc_tracer = 0;
    uint32_t zero = 0; // Look-up Key

    sc_tracer = bpf_sc_tracer_map_lookup_elem(&zero);
    if (sc_tracer) {
        uid_t uid = (uid_t)(uid_gid);
        if (uid == sc_tracer->uid) {
            return;
        }
    }
    sc_open_data_t data = {};
    data.event_time = event_time;
    data.uid_gid = uid_gid;
    data.pid_tgid = bpf_get_current_pid_tgid();

    data.dfd = (int) args->args[0];
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), POINTER_OF_USER_SPACE(args->args[1]));
    data.flags = (int) args->args[2];
    data.mode = (mode_t) args->args[3];

    uint64_t key = data.pid_tgid;
    bpf_sc_open_data_map_update_elem(&key, &data, BPF_ANY);
}

static inline __always_inline void onSyscallOpenExit(sys_exit_data_t *args) {
    uint64_t key = bpf_get_current_pid_tgid();
    sc_open_data_t *data = bpf_sc_open_data_map_lookup_elem(&key);

    if (data) {
        data->ret = args->ret;
#ifdef USE_RINGBUF
        sc_data_t *output = bpf_sc_data_ringbuf_reserve();
        if (output == NULL) return;

        output->event = TRACE_EVENT_SYS_OPEN;
        output->nr = GENERIC_SYSCALL_NR_OPEN;
        output->u.sc_open.data.dfd        = data->dfd;
        output->u.sc_open.data.flags      = data->flags;
        output->u.sc_open.data.mode       = data->mode;
        output->u.sc_open.data.event_time = data->event_time;
        output->u.sc_open.data.pid_tgid   = data->pid_tgid;
        output->u.sc_open.data.uid_gid    = data->uid_gid;
        output->u.sc_open.data.ret        = data->ret;
        __builtin_memcpy(&output->u.sc_open.data.filename, data->filename,
                         sizeof(output->u.sc_open.data.filename));

        bpf_sc_data_ringbuf_submit(output);
#endif
        bpf_sc_open_data_map_delete_elem(&key);
    }
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, sc_open_enter)
(sys_enter_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_OPEN) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallOpenEnter(args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, sc_open_exit)
(sys_exit_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_OPEN) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallOpenExit(args);
    }
    return 1;
}

LICENSE("GPL");