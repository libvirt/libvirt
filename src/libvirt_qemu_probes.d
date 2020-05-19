provider libvirt {
        # file: src/qemu/qemu_monitor.c
        # prefix: qemu
        # binary: libvirtd
        # module: libvirt/connection-driver/libvirt_driver_qemu.so
        # Monitor lifecycle
        probe qemu_monitor_new(void *mon, int fd);
        probe qemu_monitor_ref(void *mon);
        probe qemu_monitor_unref(void *mon);
        probe qemu_monitor_close(void *monm);

        # High level monitor message processing
        probe qemu_monitor_send_msg(void *mon, const char *msg, int fd);
        probe qemu_monitor_recv_reply(void *mon, const char *reply);
        probe qemu_monitor_recv_event(void *mon, const char *event);

        # Low level monitor I/O processing
        probe qemu_monitor_io_process(void *mon, const char *buf, unsigned int len);
        probe qemu_monitor_io_read(void *mon, const char *buf, unsigned int len, int ret, int errno);
        probe qemu_monitor_io_write(void *mon, const char *buf, unsigned int len, int ret, int errno);
        probe qemu_monitor_io_send_fd(void *mon, int fd, int ret, int errno);
};
