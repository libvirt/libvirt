docs_html_gen = []
docs_html_dep = []

index_api_gen = custom_target(
  'index-api',
  input: [
    newapi_xsl,
    docs_api_xml,
  ],
  output: [
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
      'libvirt-libvirt-@0@.html'.format(name),
    ],
    command: [
      xsltproc_prog, '--nonet', '-o', docs_builddir,
      '--stringparam', 'builddir', meson.project_build_root(),
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
endforeach

docs_html_paths = []

install_web_deps += docs_html_dep

foreach file : docs_html_gen
  docs_html_paths += file.full_path()
  install_web_files += '@0@:@1@'.format(file.full_path(), docs_html_dir / 'html')
endforeach

html_xslt_gen_install_dir = docs_html_dir / 'html'
html_xslt_gen = []

html_xslt_gen += {
  'name': 'index',
  'file': docs_rst2html5_gen.process('index.rst'),
  'source': 'docs' / 'html' / 'index.rst',
  'href_base': '../',
  }

# --- begin of XSLT processing ---

foreach data : html_xslt_gen
  html_filename = data['name'] + '.html'

  html_file = custom_target(
    html_filename,
    input: data.get('file', data['name'] + '.html.in'),
    output: html_filename,
    command: [
      xsltproc_prog,
      '--stringparam', 'pagesrc', data.get('source', ''),
      '--stringparam', 'builddir', meson.project_build_root(),
      '--stringparam', 'timestamp', docs_timestamp,
      '--stringparam', 'href_base', data.get('href_base', ''),
      '--nonet',
      site_xsl,
      '@INPUT@',
    ],
    depends: data.get('depends', []),
    depend_files: [ page_xsl ],
    capture: true,
    install: true,
    install_dir: html_xslt_gen_install_dir,
  )

  install_web_deps += html_file
  install_web_files += html_file.full_path() + ':' + html_xslt_gen_install_dir
endforeach

html_xslt_gen = []

# --- end of XSLT processing ---

if tests_enabled[0]
  test(
    'check-html',
    xmllint_prog,
    args: [
      '--nonet', '--noout', docs_html_paths,
    ],
    depends: docs_html_dep,
    suite: 'script'
  )
endif
