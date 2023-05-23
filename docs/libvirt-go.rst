.. meta::
   :go-import: libvirt.org/libvirt-go git https://gitlab.com/libvirt/libvirt-go.git

================================================
Obsolete libvirt Go Language API (no Go modules)
================================================

The obsolete `Go <https://golang.org/>`__ package ``libvirt.org/libvirt-go``
provided `CGo <https://golang.org/cmd/cgo/>`__ binding from the OS native
Libvirt API.

This package is replaced by the new `libvirt.org/go/libvirt <go/libvirt.html>`__
package in order to switch to using `semver <https://semver.org/>`__ and
`Go modules <https://golang.org/ref/mod>`__. Aside from the changed
import path and versioning scheme, the new package API is fully compatible
with this legacy package.

Software currently using this package will keep working, but no further
development will take place. libvirt APIs/constants introduced after
7.4.0 will never be available. Authors are strongly recommended to switch
imports to point to the new package, to prepare for future Go toolchains
which will mandate Go module support and semver.

In general the Go representation is a direct 1-1 mapping from native API
concepts to Go, so the native API documentation should serve as a reference
for most behaviour.

For details of Go specific behaviour consult the
`Go package documentation <https://pkg.go.dev/libvirt.org/libvirt-go>`__.
