apipng = [
  'home.png',
  'left.png',
  'right.png',
  'up.png',
]

install_data(apipng, install_dir: docs_html_dir / 'html')

custom_target(
  'index-api',
  input: [
    newapi_xsl,
    docs_api_xml,
  ],
  output: [
    'index.html',
    'libvirt-libvirt-common.html',
    'libvirt-libvirt-domain.html',
    'libvirt-libvirt-domain-checkpoint.html',
    'libvirt-libvirt-domain-snapshot.html',
    'libvirt-libvirt-event.html',
    'libvirt-libvirt-host.html',
    'libvirt-libvirt-interface.html',
    'libvirt-libvirt-network.html',
    'libvirt-libvirt-nodedev.html',
    'libvirt-libvirt-nwfilter.html',
    'libvirt-libvirt-secret.html',
    'libvirt-libvirt-storage.html',
    'libvirt-libvirt-stream.html',
    'libvirt-virterror.html',
  ],
  command: [
    xsltproc_prog, '--nonet', '-o', docs_builddir,
    '--stringparam', 'builddir', meson.build_root(),
    '--stringparam', 'timestamp', docs_timestamp,
    '@INPUT@',
  ],
  install: true,
  install_dir: docs_html_dir / 'html',
  depend_files: [
    page_xsl,
  ],
)

foreach name : [ 'admin', 'lxc', 'qemu' ]
  custom_target(
    'index-@0@-api'.format(name),
    input: [
      newapi_xsl,
      get_variable('docs_@0@_api_xml'.format(name)),
    ],
    output: [
      'index-@0@.html'.format(name),
      'libvirt-libvirt-@0@.html'.format(name),
    ],
    command: [
      xsltproc_prog, '--nonet', '-o', docs_builddir,
      '--stringparam', 'builddir', meson.build_root(),
      '--stringparam', 'timestamp', docs_timestamp,
      '--stringparam', 'indexfile', 'index-@0@.html'.format(name),
      '@INPUT@',
    ],
    install: true,
    install_dir: docs_html_dir / 'html',
    depend_files: [
      page_xsl,
    ],
  )
endforeach
