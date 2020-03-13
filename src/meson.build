src_inc_dir = include_directories('.')

src_dep = declare_dependency(
  compile_args: [
    '-DIN_LIBVIRT',
    '-Dabs_top_builddir="@0@"'.format(meson.build_root()),
    '-Dabs_top_srcdir="@0@"'.format(meson.source_root()),
  ] + coverage_flags + win32_flags,
  dependencies: [
    glib_dep,
    libxml_dep,
  ],
  include_directories: [
    libvirt_inc,
    src_inc_dir,
    top_inc_dir,
  ],
  link_args: (
    libvirt_relro
    + libvirt_no_indirect
    + coverage_flags
    + driver_modules_flags
    + win32_link_flags
  ),
)


# define secdriver_dep

secdriver_dep = []
if conf.has('WITH_SECDRIVER_SELINUX')
  secdriver_dep += selinux_dep
endif
if conf.has('WITH_SECDRIVER_APPARMOR')
  secdriver_dep += apparmor_dep
endif


# generate systemtap files

systemtap_dir = datadir / 'systemtap' / 'tapset'

dtrace_gen_headers = []
dtrace_gen_objects = []

if conf.has('WITH_DTRACE_PROBES')
  infile = 'libvirt_probes.d'
  out_h = 'libvirt_probes.h'
  out_o = 'libvirt_probes.o'
  out_stp = 'libvirt_probes.stp'

  dtrace_gen_headers += custom_target(
    out_h,
    input: infile,
    output: out_h,
    command: [ dtrace_prog, '-o', '@OUTPUT@', '-h', '-s', '@INPUT@' ],
  )

  dtrace_gen_objects += custom_target(
    out_o,
    input: infile,
    output: out_o,
    command: [ dtrace_prog, '-o', '@OUTPUT@', '-G', '-s', '@INPUT@' ],
  )

  custom_target(
    out_stp,
    input: infile,
    output: out_stp,
    command: [
      meson_python_prog, python3_prog.path(), dtrace2systemtap_prog.path(),
      bindir, sbindir, libdir, '@INPUT@'
    ],
    capture: true,
    install: true,
    install_dir: systemtap_dir,
  )
endif


# list subdirectories

subdir('util')

src_dep = declare_dependency(
  dependencies: [ src_dep ],
  include_directories: [ util_inc_dir ],
)

subdir('conf')
subdir('rpc')
subdir('access')
subdir('cpu')

subdir('hypervisor')
subdir('vmx')

subdir('admin')
subdir('locking')
subdir('logging')

subdir('esx')
subdir('hyperv')
subdir('openvz')
subdir('test')
subdir('vmware')
