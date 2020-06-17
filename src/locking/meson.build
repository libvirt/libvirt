lock_protocol = 'lock_protocol.x'

lock_driver_sources = [
  'lock_manager.c',
  'lock_driver_nop.c',
  'domain_lock.c',
]

lock_driver_lockd_sources = [
  'lock_driver_lockd.c',
]

lock_protocol_generated = []

lock_protocol_generated += custom_target(
  'lock_protocol.h',
  input: lock_protocol,
  output: 'lock_protocol.h',
  command: [
    genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@',
  ],
)

lock_protocol_generated += custom_target(
  'lock_protocol.c',
  input: lock_protocol,
  output: 'lock_protocol.c',
  command: [
    genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@',
  ],
)

lock_driver_lib = static_library(
  'virt_lock_driver',
  [
    lock_driver_sources,
  ],
  dependencies: [
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)

libvirt_libs += lock_driver_lib

if conf.has('WITH_LIBVIRTD')
  lockd_lib_impl = static_library(
    'lockd_impl',
    [
      files(lock_driver_lockd_sources),
      lock_protocol_generated,
    ],
    include_directories: [
      conf_inc_dir,
    ],
    dependencies: [
      rpc_dep,
      sasl_dep,
      src_dep,
      xdr_dep,
    ],
  )
endif
