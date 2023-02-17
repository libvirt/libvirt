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
    '--stringparam', 'builddir', meson.project_build_root(),
    '--stringparam', 'aclxmlpath', docs_acl_xml.full_path(),
    '--stringparam', 'timestamp', docs_timestamp,
    '--stringparam', 'indexfile', 'index.html',
    '@INPUT@',
  ],
  install: true,
  install_dir: docs_html_dir / 'html',
  depends: docs_acl_xml,
  depend_files: [
    page_xsl,
  ],
)

docs_html_gen += index_api_gen.to_list()
docs_html_dep += index_api_gen

foreach name : [ 'lxc', 'qemu' ]
  index_api_gen = custom_target(
    'index-@0@-api'.format(name),
    input: [
      newapi_xsl,
      get_variable('docs_@0@_api_xml'.format(name)),
    ],
    output: [
      'libvirt-libvirt-@0@.html'.format(name),
    ],
    command: [
      xsltproc_prog, '--nonet', '-o', docs_builddir,
      '--stringparam', 'builddir', meson.project_build_root(),
      '--stringparam', 'aclxmlpath', get_variable('docs_acl_@0@_xml'.format(name)).full_path(),
      '--stringparam', 'timestamp', docs_timestamp,
      '@INPUT@',
    ],
    install: true,
    install_dir: docs_html_dir / 'html',
    depends:  get_variable('docs_acl_@0@_xml'.format(name)),
    depend_files: [
      page_xsl,
    ],
  )

  docs_html_gen += index_api_gen.to_list()
  docs_html_dep += index_api_gen
endforeach

index_api_gen = custom_target(
  'index-admin-api'.format(name),
  input: [
    newapi_xsl,
    docs_admin_api_xml,
    ],
  output: [
    'libvirt-libvirt-admin.html'
    ],
  command: [
    xsltproc_prog, '--nonet', '-o', docs_builddir,
    '--stringparam', 'builddir', meson.project_build_root(),
    '--stringparam', 'aclxmlpath', '',
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
