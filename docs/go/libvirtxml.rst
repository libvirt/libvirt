.. meta::
   :go-import: libvirt.org/go/libvirtxml git https://gitlab.com/libvirt/libvirt-go-xml-module.git

============================================
Libvirt Go XML parsing API (with Go modules)
============================================

The `Go <https://golang.org/>`__ package ``libvirt.org/go/libvirtxml`` provides
annotated Go struct definitions for parsing (and formatting) XML documents used
with libvirt APIs.

This package replaces the obsolete `libvirt.org/libvirt-go-xml
<../libvirt-go-xml.html>`__ package in order to switch to using `semver
<https://semver.org/>`__ and `Go modules <https://golang.org/ref/mod>`__.
Aside from the changed import path and versioning scheme, the API is fully
compatible with the original package.

For details of Go specific behaviour consult the
`Go package documentation <https://pkg.go.dev/libvirt.org/go/libvirtxml>`__.
