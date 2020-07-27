vmx_sources = [
  'vmx.c',
]

if conf.has('WITH_VMX')
  vmx_lib = static_library(
    'virt_vmx',
    [
      vmx_sources,
    ],
    dependencies: [
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  libvirt_libs += vmx_lib
endif

vmx_inc_dir = include_directories('.')

if conf.has('WITH_VMX')
  used_sym_files += 'libvirt_vmx.syms'
else
  sym_files += 'libvirt_vmx.syms'
endif
