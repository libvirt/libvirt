provider libvirtd {
	 probe client_connect(int fd, int readonly, const char *localAddr, const char *remoteAddr);
	 probe client_disconnect(int fd);

	 probe client_auth_allow(int fd, int authtype, const char *identity);
	 probe client_auth_deny(int fd, int authtype, const char *identity);
	 probe client_auth_fail(int fd, int authtype);

	 probe client_tls_allow(int fd, const char *x509dname);
	 probe client_tls_deny(int fd, const char *x509dname);
	 probe client_tls_fail(int fd);
};
