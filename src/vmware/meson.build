vmware_sources = [
  'vmware_conf.c',
  'vmware_driver.c',
]

if conf.has('WITH_VMWARE')
  vmware_lib = static_library(
    'virt_vmware',
    vmware_sources,
    dependencies: [
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      vmx_inc_dir,
    ],
  )

  libvirt_libs += vmware_lib
endif

if conf.has('WITH_VMWARE')
  used_sym_files += 'libvirt_vmware.syms'
else
  sym_files += 'libvirt_vmware.syms'
endif
