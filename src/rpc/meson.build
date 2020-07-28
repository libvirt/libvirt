genprotocol_prog = find_program('genprotocol.pl')
gendispatch_prog = find_program('gendispatch.pl')

rpc_sources = [
  'virnetmessage.c',
  'virnettlscontext.c',
  'virnetsocket.c',
  'virkeepalive.c',
]

if libssh_dep.found()
  rpc_sources += 'virnetlibsshsession.c'
endif

if libssh2_dep.found()
  rpc_sources += 'virnetsshsession.c'
endif

if sasl_dep.found()
  rpc_sources += 'virnetsaslcontext.c'
endif

rpc_gen_headers = []
rpc_gen_sources = []

foreach name : [ 'virnet', 'virkeepalive' ]
  protocol_file = files('@0@protocol.x'.format(name))
  header_file = '@0@protocol.h'.format(name)
  source_file = '@0@protocol.c'.format(name)

  rpc_gen_headers += custom_target(
    header_file,
    input: protocol_file,
    output: header_file,
    command: [
      genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@',
    ],
  )

  rpc_gen_sources += custom_target(
    source_file,
    input: protocol_file,
    output: source_file,
    command: [
      genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@',
    ],
  )

  rpc_probe_files += protocol_file
endforeach

rpc_server_sources = [
  'virnetserverprogram.c',
  'virnetserverservice.c',
  'virnetserverclient.c',
  'virnetdaemon.c',
  'virnetserver.c',
]

rpc_client_sources = [
  'virnetclientprogram.c',
  'virnetclientstream.c',
  'virnetclient.c',
]

virt_rpc_lib = static_library(
  'virt_net_rpc',
  [
    rpc_sources,
    rpc_gen_headers,
    rpc_gen_sources,
  ],
  dependencies: [
    gnutls_dep,
    libssh2_dep,
    libssh_dep,
    sasl_dep,
    secdriver_dep,
    src_dep,
    xdr_dep,
  ],
)

check_protocols += {
  'name': 'virnetprotocol',
  'lib': virt_rpc_lib,
}

check_protocols += {
  'name': 'virkeepaliveprotocol',
  'lib': virt_rpc_lib,
}

virt_rpc_server_lib = static_library(
  'virt_net_rpc_server',
  [
    rpc_server_sources,
    rpc_gen_headers,
  ],
  dependencies: [
    dbus_dep,
    sasl_dep,
    src_dep,
    xdr_dep,
  ],
)

virt_rpc_client_lib = static_library(
  'virt_net_rpc_client',
  [
    rpc_client_sources,
    rpc_gen_headers,
  ],
  dependencies: [
    sasl_dep,
    src_dep,
    xdr_dep,
  ],
)

rpc_inc_dir = include_directories('.')

rpc_dep = declare_dependency(
  include_directories: [ rpc_inc_dir ],
  sources: [ rpc_gen_headers ],
)

libvirt_libs += [
  virt_rpc_lib,
  virt_rpc_client_lib,
  virt_rpc_server_lib,
]
