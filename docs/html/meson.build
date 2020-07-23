apipng = [
  'home.png',
  'left.png',
  'right.png',
  'up.png',
]

install_data(apipng, install_dir: docs_html_dir / 'html')

foreach file : apipng
  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir / 'html')
endforeach

docs_html_gen = []
docs_html_dep = []

index_api_gen = custom_target(
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

docs_html_gen += index_api_gen.to_list()
docs_html_dep += index_api_gen

foreach name : [ 'admin', 'lxc', 'qemu' ]
  index_api_gen = custom_target(
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

  docs_html_gen += index_api_gen.to_list()
  docs_html_dep += index_api_gen
endforeach

docs_html_paths = []

install_web_deps += docs_html_dep

foreach file : docs_html_gen
  docs_html_paths += file.full_path()
  install_web_files += '@0@:@1@'.format(file.full_path(), docs_html_dir / 'html')
endforeach

test(
  'check-html',
  xmllint_prog,
  args: [
    '--nonet', '--noout', docs_html_paths,
  ],
  depends: docs_html_dep,
)
