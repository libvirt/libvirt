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

nss_guest_sources = [
  'libvirt_nss_macs.c',
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

nss_libvirt_guest_impl = static_library(
  'nss_libvirt_guest_impl',
  [
    nss_sources,
    nss_guest_sources,
  ],
  c_args: [
    '-DLIBVIRT_NSS',
    '-DLIBVIRT_NSS_GUEST',
  ],
  dependencies: [
    tools_dep,
    yajl_dep,
  ],
)

nss_libvirt_syms_file = meson.current_source_dir() / nss_sym_file
nss_libvirt_syms_path = nss_libvirt_syms_file

nss_libvirt_link_args = [
  libvirt_export_dynamic,
  coverage_flags,
]

if version_script_flags != ''
  nss_libvirt_link_args += '@0@@1@'.format(
    version_script_flags,
    nss_libvirt_syms_path,
  )
endif

nss_libvirt_lib = shared_library(
  'nss_libvirt',
  name_prefix: nss_prefix,
  name_suffix: 'so.@0@'.format(nss_so_ver),
  link_args: nss_libvirt_link_args,
  link_whole: [
    nss_libvirt_impl,
  ],
  install: true,
  install_dir: libdir,
)

nss_libvirt_guest_syms_file = meson.current_source_dir() / nss_guest_sym_file
nss_libvirt_guest_syms_path = nss_libvirt_guest_syms_file

nss_libvirt_guest_link_args = [
  libvirt_export_dynamic,
  coverage_flags,
]

if version_script_flags != ''
  nss_libvirt_guest_link_args += '@0@@1@'.format(
    version_script_flags,
    nss_libvirt_guest_syms_path,
  )
endif

nss_libvirt_guest_lib = shared_library(
  'nss_libvirt_guest',
  name_prefix: nss_prefix,
  name_suffix: 'so.@0@'.format(nss_so_ver),
  link_args: nss_libvirt_guest_link_args,
  link_whole: [
    nss_libvirt_guest_impl,
  ],
  install: true,
  install_dir: libdir,
)

nss_inc_dir = include_directories('.')
