log_driver_sources = [
  'log_manager.c',
]

log_protocol = 'log_protocol.x'

log_protocol_generated = []

log_protocol_generated += custom_target(
  'log_protocol.h',
  input: log_protocol,
  output: 'log_protocol.h',
  command: [
    genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@'
  ],
)

log_protocol_generated += custom_target(
  'log_protocol.c',
  input: log_protocol,
  output: 'log_protocol.c',
  command: [
    genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@'
  ],
)

log_driver_lib = static_library(
  'virt_log_driver',
  [
    log_driver_sources,
    log_protocol_generated,
  ],
  dependencies: [
    rpc_dep,
    src_dep,
    xdr_dep,
  ],
)
