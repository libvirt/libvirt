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
  { 'name': 'virt-pki-validate', 'section': '1', 'install': true },
  { 'name': 'virt-qemu-run', 'section': '1', 'install': conf.has('WITH_QEMU') },
  { 'name': 'virt-xml-validate', 'section': '1', 'install': true },

  { 'name': 'libvirtd', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'virt-sanlock-cleanup', 'section': '8', 'install': conf.has('WITH_SANLOCK') },
  { 'name': 'virtlockd', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
  { 'name': 'virtlogd', 'section': '8', 'install': conf.has('WITH_LIBVIRTD') },
]

foreach name : keycode_list
  rst_file = custom_target(
    'virkeycode-@0@.rst'.format(name),
    input: keymap_src_file,
    output: 'virkeycode-@0@.rst'.format(name),
    command: [
      meson_python_prog, python3_prog.path(), keymap_gen_prog.path(), 'code-docs',
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
      meson_python_prog, python3_prog.path(), keymap_gen_prog.path(), 'name-docs',
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

docs_man_conf = configuration_data()
docs_man_conf.set('SYSCONFDIR', sysconfdir)
docs_man_conf.set('RUNSTATEDIR', runstatedir)

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
    command: [ rst2html_prog, '--stylesheet=', '--strict', '@INPUT@' ],
    capture: true,
  )

  out_file = custom_target(
    html_file,
    input: html_in,
    output: html_file,
    command: [
      meson_python_prog,
      python3_prog.path(),
      meson_html_gen_prog.path(),
      xsltproc_prog.path(),
      xmllint_prog.path(),
      meson.build_root(),
      docs_timestamp,
      subsite_xsl,
      '@INPUT@',
      '@OUTPUT@',
      'docs/manpages' / rst_in_file,
    ],
    depends: [ aclperms_gen ],
    depend_files: [ page_xsl ],
    install: true,
    install_dir: docs_html_dir / 'manpages',
  )

  install_web_deps += out_file
  install_web_files += '@0@:@1@'.format(out_file.full_path(), docs_html_dir / 'manpages')
endforeach
