.. meta::
   :go-import: libvirt.org/go/libvirt git https://gitlab.com/libvirt/libvirt-go-module.git

=========================================
Libvirt Go Language API (with Go modules)
=========================================

The `Go <https://golang.org/>`__ package ``libvirt.org/go/libvirt`` provides
`CGo <https://golang.org/cmd/cgo/>`__ binding from the OS native Libvirt API.

This package replaces the obsolete `libvirt.org/libvirt-go
<../libvirt-go.html>`__ package in order to switch to using `semver
<https://semver.org/>`__ and `Go modules <https://golang.org/ref/mod>`__.
Aside from the changed import path and versioning scheme, the API is fully
compatible with the legacy package.

In general the Go representation is a direct 1-1 mapping from native API
concepts to Go, so the native API documentation should serve as a reference
for most behaviour.

For details of Go specific behaviour consult the
`Go package documentation <https://pkg.go.dev/libvirt.org/go/libvirt>`__.
