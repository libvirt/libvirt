admin_driver_sources = [
  'admin_server.c',
  'admin_server_dispatch.c',
]

admin_driver_protocol = files('admin_protocol.x')

admin_driver_generated = []

admin_driver_generated += custom_target(
  'admin_protocol.h',
  input: admin_driver_protocol,
  output: 'admin_protocol.h',
  command: [
    genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@',
  ],
)

admin_driver_generated += custom_target(
  'admin_protocol.c',
  input: admin_driver_protocol,
  output: 'admin_protocol.c',
  command: [
    genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@',
  ],
)

admin_driver_generated += custom_target(
  'admin_server_dispatch_stubs.h',
  input: admin_driver_protocol,
  output: 'admin_server_dispatch_stubs.h',
  command: [
    gendispatch_prog, '--mode=server', 'admin', 'ADMIN', '@INPUT@',
  ],
  capture: true,
)

admin_driver_lib = static_library(
  'virt_admin_driver',
  [
    admin_driver_sources,
    admin_driver_generated,
  ],
  dependencies: [
    rpc_dep,
    sasl_dep,
    src_dep,
    xdr_dep,
  ],
)
