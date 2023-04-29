html_xslt_gen_install_dir = docs_html_dir / 'manpages'
html_xslt_gen = []

# docs_man_files
#   each entry is a dictionary with following items:
#   name - man page name (required)
#   section - man page section (required)
#   install - whether to build and install the man page (required)
#   file - generated RST file (optional, default none)

docs_man_files = [
  { 'name': 'index', 'section': '', 'install': false },

  { 'name': 'virsh', 'section': '1', 'install': true },
  { 'name': 'virt-admin', 'section': '1', 'install': true },
  { 'name': 'virt-host-validate', 'section': '1', 'install': conf.has('WITH_HOST_VALIDATE') },
  { 'name': 'virt-login-shell', 'section': '1', 'install': conf.has('WITH_LOGIN_SHELL') },
  { 'name': 'virt-pki-query-dn', 'section': '1', 'install': true },
  { 'name': 'virt-pki-validate', 'section': '1', 'install': true },
  { 'name': 'virt-qemu-run', 'section': '1', 'install': conf.has('WITH_QEMU') },
  { 'name': 'virt-qemu-qmp-proxy', 'section': '1', 'install': conf.has('WITH_QEMU') },
  { 'name': 'virt-xml-validate', 'section': '1', 'install': true },
  { 'name': 'virt-qemu-sev-validate', 'section': '1', 'install': conf.has('WITH_QEMU') },

  { 'name': 'libvirt-guests', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'libvirtd', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'virt-sanlock-cleanup', 'section': '8', 'install': conf.has('WITH_SANLOCK') },
  { 'name': 'virt-ssh-helper', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'virtbhyved', 'section': '8', 'install': conf.has('WITH_BHYVE') },
  { 'name': 'virtinterfaced', 'section': '8', 'install': conf.has('WITH_INTERFACE') },
  { 'name': 'virtlockd', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'virtlogd', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'virtlxcd', 'section': '8', 'install': conf.has('WITH_LXC') },
  { 'name': 'virtnetworkd', 'section': '8', 'install': conf.has('WITH_NETWORK') },
  { 'name': 'virtnodedevd', 'section': '8', 'install': conf.has('WITH_NODE_DEVICES') },
  { 'name': 'virtnwfilterd', 'section': '8', 'install': conf.has('WITH_NWFILTER') },
  { 'name': 'virtproxyd', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'virtqemud', 'section': '8', 'install': conf.has('WITH_QEMU') },
  { 'name': 'virtsecretd', 'section': '8', 'install': conf.has('WITH_SECRETS') },
  { 'name': 'virtstoraged', 'section': '8', 'install': conf.has('WITH_STORAGE') },
  { 'name': 'virtvboxd', 'section': '8', 'install': conf.has('WITH_VBOX') },
  { 'name': 'virtvzd', 'section': '8', 'install': conf.has('WITH_VZ') },
  { 'name': 'virtxend', 'section': '8', 'install': conf.has('WITH_LIBXL') },
]

foreach name : keycode_list
  rst_file = custom_target(
    'virkeycode-@0@.rst'.format(name),
    input: keymap_src_file,
    output: 'virkeycode-@0@.rst'.format(name),
    command: [
      keymap_gen_prog, 'code-docs',
      '--lang', 'rst',
      '--title', 'virkeycode-@0@'.format(name),
      '--subtitle', 'Key code values for @0@'.format(name),
      '@INPUT@', name,
    ],
    capture: true,
    build_by_default: true,
  )

  docs_man_files += {
    'name': 'virkeycode-@0@'.format(name), 'section': '7', 'install': true, 'file': rst_file,
  }
endforeach

foreach name : keyname_list
  rst_file = custom_target(
    'virkeyname-@0@.rst'.format(name),
    input: keymap_src_file,
    output: 'virkeyname-@0@.rst'.format(name),
    command: [
      keymap_gen_prog, 'name-docs',
      '--lang', 'rst',
      '--title', 'virkeyname-@0@'.format(name),
      '--subtitle', 'Key name values for @0@'.format(name),
      '@INPUT@', name,
    ],
    capture: true,
    build_by_default: true,
  )

  docs_man_files += {
    'name': 'virkeyname-@0@'.format(name), 'section': '7', 'install': true, 'file': rst_file,
  }
endforeach

docs_man_conf = configuration_data({
  'SYSCONFDIR': sysconfdir,
  'RUNSTATEDIR': runstatedir,
  'INITCONFDIR': initconfdir,
  'VERSION': meson.project_version(),
})

foreach data : docs_man_files
  rst_in_file = '@0@.rst'.format(data['name'])
  html_in_file = '@0@.html.in'.format(data['name'])
  html_file = '@0@.html'.format(data['name'])

  if data.has_key('file')
    rst_file = data['file']
  else
    rst_file = configure_file(
      input: rst_in_file,
      output: '@0@.rst'.format(data['name']),
      configuration: docs_man_conf,
    )
  endif

  if data['install']
    man_file = '@0@.@1@'.format(data['name'], data['section'])
    man_page = custom_target(
      man_file,
      input: rst_file,
      output: man_file,
      # 'contents' element is the table of contents which is undesired in manpage
      command: [ rst2man_prog, '--strip-elements-with-class', 'contents', '--strict', '@INPUT@', '@OUTPUT@' ],
      install: true,
      install_dir: mandir / 'man@0@'.format(data['section']),
    )
  endif

  html_in = custom_target(
    html_in_file,
    input: rst_file,
    output: html_in_file,
    command: [ rst2html5_prog, '--stylesheet=', '--strict', '@INPUT@' ],
    capture: true,
  )

  html_xslt_gen += {
    'name': data['name'],
    'file': html_in,
    'source': 'docs' / 'manpages' / rst_in_file,
    'href_base': '../',
  }
endforeach

# keep the XSLT processing code block in sync with docs/meson.build

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
