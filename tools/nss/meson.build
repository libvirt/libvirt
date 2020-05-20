if conf.has('WITH_BSD_NSS')
  nss_sym_file = 'libvirt_nss_bsd.syms'
  nss_guest_sym_file = nss_sym_file
  nss_so_ver = '1'
  nss_prefix = ''
else
  nss_sym_file = 'libvirt_nss.syms'
  nss_guest_sym_file = 'libvirt_guest_nss.syms'
  nss_so_ver = '2'
  nss_prefix = 'lib'
endif

nss_sources = [
  'libvirt_nss.c',
  'libvirt_nss_leases.c',
]

nss_libvirt_impl = static_library(
  'nss_libvirt_impl',
  [
    nss_sources,
  ],
  c_args: [
    '-DLIBVIRT_NSS'
  ],
  dependencies: [
    tools_dep,
    yajl_dep,
  ],
)
