provider libvirt {
	# file: src/util/event_poll.c
	# prefix: event_poll
	probe event_poll_add_handle(int watch, int fd, int events, void *cb, void *opaque, void *ff);
	probe event_poll_update_handle(int watch, int events);
	probe event_poll_remove_handle(int watch);
	probe event_poll_dispatch_handle(int watch, int events);
	probe event_poll_purge_handle(int watch);

	probe event_poll_add_timeout(int timer, int frequency, void *cb, void *opaque, void *ff);
	probe event_poll_update_timeout(int timer, int frequency);
	probe event_poll_remove_timeout(int timer);
	probe event_poll_dispatch_timeout(int timer);
	probe event_poll_purge_timeout(int timer);

	probe event_poll_run(int nfds, int timeout);

	# file: src/util/virdbus.c
	# prefix: dbus
	probe dbus_method_call(const char *interface, const char *member, const char *object, const char *destination);
	probe dbus_method_error(const char *interface, const char *member, const char *object, const char *destination, const char *name, const char *message);
	probe dbus_method_reply(const char *interface, const char *member, const char *object, const char *destination);

        # file: src/util/virobject.c
        # prefix: object
        probe object_new(void *obj, const char *klassname);
        probe object_ref(void *obj);
        probe object_unref(void *obj);
        probe object_dispose(void *obj);

	# file: src/rpc/virnetsocket.c
	# prefix: rpc
	probe rpc_socket_new(void *sock, int fd, int errfd, pid_t pid, const char *localAddr, const char *remoteAddr);
	probe rpc_socket_dispose(void *sock);
	probe rpc_socket_send_fd(void *sock, int fd);
	probe rpc_socket_recv_fd(void *sock, int fd);


	# file: src/rpc/virnetserverclient.c
	# prefix: rpc
	probe rpc_server_client_new(void *client, void *sock);
	probe rpc_server_client_dispose(void *client);
	probe rpc_server_client_msg_tx_queue(void *client, int len, int prog, int vers, int proc, int type, int status, int serial);
	probe rpc_server_client_msg_rx(void *client, int len, int prog, int vers, int proc, int type, int status, int serial);


	# file: src/rpc/virnetclient.c
	# prefix: rpc
	probe rpc_client_new(void *client, void *sock);
	probe rpc_client_dispose(void *client);
	probe rpc_client_msg_tx_queue(void *client, int len, int prog, int vers, int proc, int type, int status, int serial);
	probe rpc_client_msg_rx(void *client, int len, int prog, int vers, int proc, int type, int status, int serial);


	# file: daemon/libvirtd.c
	# prefix: rpc
	probe rpc_server_client_auth_allow(void *client, int authtype, const char *identity);
	probe rpc_server_client_auth_deny(void *client, int authtype, const char *identity);
	probe rpc_server_client_auth_fail(void *client, int authtype);


	# file: src/rpc/virnettlscontext.c
	# prefix: rpc
	probe rpc_tls_context_new(void *ctxt, const char *cacert, const char *cacrl,
				  const char *cert, const char *key, int sanityCheckCert, int requireValidCert, int isServer);
	probe rpc_tls_context_dispose(void *ctxt);
	probe rpc_tls_context_session_allow(void *ctxt, void *sess, const char *dname);
	probe rpc_tls_context_session_deny(void *ctxt, void *sess, const char *dname);
	probe rpc_tls_context_session_fail(void *ctxt, void *sess);


	probe rpc_tls_session_new(void *sess, void *ctxt, const char *hostname, int isServer);
	probe rpc_tls_session_dispose(void *sess);
	probe rpc_tls_session_handshake_pass(void *sess);
	probe rpc_tls_session_handshake_fail(void *sess);


	# file: src/rpc/virkeepalive.c
	# prefix: rpc
	probe rpc_keepalive_new(void *ka, void *client);
	probe rpc_keepalive_dispose(void *ka);
	probe rpc_keepalive_start(void *ka, void *client, int interval, int count);
	probe rpc_keepalive_stop(void *ka, void *client);
	probe rpc_keepalive_send(void *ka, void *client, int prog, int vers, int proc);
	probe rpc_keepalive_received(void *ka, void *client, int prog, int vers, int proc);
	probe rpc_keepalive_timeout(void *ka, void *client, int coundToDeath, int idle);
};
