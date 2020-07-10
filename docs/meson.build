docs_html_dir = docdir / 'html'

# xsltproc requires that the -o path ends with '/'
docs_builddir = meson.current_build_dir() / ''

docs_assets = [
  'android-chrome-192x192.png',
  'android-chrome-256x256.png',
  'apple-touch-icon.png',
  'architecture.gif',
  'browserconfig.xml',
  'favicon.ico',
  'favicon-16x16.png',
  'favicon-32x32.png',
  'generic.css',
  'libvirt.css',
  'libvirt-daemon-arch.png',
  'libvirt-driver-arch.png',
  'libvirt-object-model.png',
  'libvirt-virConnect-example.png',
  'main.css',
  'manifest.json',
  'migration-managed-direct.png',
  'migration-managed-p2p.png',
  'migration-native.png',
  'migration-tunnel.png',
  'migration-unmanaged-direct.png',
  'mobile.css',
  'mstile-150x150.png',
  'node.gif',
]

docs_html_in_files = [
  '404',
  'acl',
  'aclpolkit',
  'api_extension',
  'api',
  'apps',
  'architecture',
  'auditlog',
  'auth',
  'bindings',
  'bugs',
  'cgroups',
  'compiling',
  'contact',
  'contribute',
  'csharp',
  'dbus',
  'devguide',
  'docs',
  'downloads',
  'drivers',
  'drvbhyve',
  'drvesx',
  'drvhyperv',
  'drvlxc',
  'drvnodedev',
  'drvopenvz',
  'drvqemu',
  'drvremote',
  'drvsecret',
  'drvtest',
  'drvvbox',
  'drvvirtuozzo',
  'drvvmware',
  'drvxen',
  'errors',
  'firewall',
  'formatcaps',
  'formatdomaincaps',
  'format',
  'formatnetwork',
  'formatnetworkport',
  'formatnode',
  'formatnwfilter',
  'formatsecret',
  'formatsnapshot',
  'formatstoragecaps',
  'formatstorageencryption',
  'formatstorage',
  'goals',
  'governance',
  'hooks',
  'index',
  'internals',
  'java',
  'logging',
  'migration',
  'nss',
  'pci-hotplug',
  'php',
  'python',
  'remote',
  'securityprocess',
  'storage',
  'strategy',
  'support',
  'testapi',
  'testsuites',
  'testtck',
  'tlscerts',
  'uri',
  'virshcmdref',
  'windows',
]

docs_rst_files = [
  'advanced-tests',
  'best-practices',
  'ci',
  'coding-style',
  'committer-guidelines',
  'daemons',
  'developer-tooling',
  'formatbackup',
  'formatcheckpoint',
  'formatdomain',
  'hacking',
  'kbase',
  'libvirt-go',
  'libvirt-go-xml',
  'newreposetup',
  'pci-addresses',
  'platforms',
  'programming-languages',
  'styleguide',
  'submitting-patches',
]

# list of web targets to build for docs/web rule
install_web_deps = []
install_web_files = []

install_data(docs_assets, install_dir: docs_html_dir)

aclperms_gen = custom_target(
  'aclperms.htmlinc',
  input: access_perm_h,
  output: 'aclperms.htmlinc',
  command: [
    meson_python_prog, python3_prog.path(), genaclperms_prog.path(), '@INPUT@',
  ],
  capture: true,
)

docs_timestamp = run_command(
  python3_prog, meson_timestamp_prog.path(), env: runutf8
).stdout().strip()

site_xsl = files('site.xsl')
subsite_xsl = files('subsite.xsl')
page_xsl = files('page.xsl')
newapi_xsl = files('newapi.xsl')

docs_api_generated = custom_target(
  'generate-api',
  output: [
    'libvirt-api.xml',
    'libvirt-lxc-api.xml',
    'libvirt-qemu-api.xml',
    'libvirt-admin-api.xml',
  ],
  command: [
    meson_python_prog, python3_prog.path(), apibuild_prog.path(),
    meson.current_source_dir(),
    meson.current_build_dir(),
  ],
  install: true,
  install_dir: pkgdatadir / 'api',
  depend_files: [
    libvirt_common_h_in,
    libvirt_include,
    driver_sources,
    libvirt_qemu_sources,
    libvirt_lxc_sources,
    admin_sources,
    util_public_sources,
  ],
)

docs_api_xml = docs_api_generated[0]
docs_lxc_api_xml = docs_api_generated[1]
docs_qemu_api_xml = docs_api_generated[2]
docs_admin_api_xml = docs_api_generated[3]

docs_rst2html_gen = generator(
  rst2html_prog,
  output: '@BASENAME@.html.in',
  arguments: [ '--stylesheet=', '--strict', '@INPUT@' ],
  capture: true,
)


# docs_html_in_gen:
#   each entry is a dictionary with following items:
#   name - base file name (required)
#   file - generated file (required)
# source - source filename relative to repository root (optional, if there is no source)
docs_html_in_gen = []

foreach name : docs_html_in_files
  html_in_file = '@0@.html.in'.format(name)
  docs_html_in_gen += {
    'name': name,
    'file': html_in_file,
    'source': 'docs' / html_in_file,
  }
endforeach

foreach name : docs_rst_files
  rst_file = '@0@.rst'.format(name)
  docs_html_in_gen += {
    'name': name,
    'file': docs_rst2html_gen.process(rst_file),
    'source': 'docs' / rst_file,
  }
endforeach

hvsupport_html_in = custom_target(
  'hvsupport.html.in',
  output: 'hvsupport.html.in',
  command: [
    meson_python_prog,
    python3_prog.path(),
    hvsupport_prog.path(),
    meson.source_root(),
    meson.build_root(),
  ],
  capture: true,
  depend_files: [
    public_sym_file,
    libvirt_qemu_syms,
    libvirt_lxc_syms,
    driver_header,
  ],
  depends: [
    docs_api_generated,
  ],
)
docs_html_in_gen += {
  'name': 'hvsupport',
  'file': hvsupport_html_in,
}

news_html_in = docs_rst2html_gen.process(meson.source_root() / 'NEWS.rst')
docs_html_in_gen += {
  'name': 'news',
  'file': news_html_in,
  'source': 'NEWS.rst',
}

foreach data : docs_html_in_gen
  html_file = '@0@.html'.format(data['name'])

  out_file = custom_target(
    html_file,
    input: data['file'],
    output: html_file,
    command: [
      meson_python_prog,
      python3_prog.path(),
      meson_html_gen_prog.path(),
      xsltproc_prog.path(),
      xmllint_prog.path(),
      meson.build_root(),
      docs_timestamp,
      site_xsl,
      '@INPUT@',
      '@OUTPUT@',
      data.get('source', []),
    ],
    depends: [ aclperms_gen ],
    depend_files: [ page_xsl ],
    install: true,
    install_dir: docs_html_dir,
  )

  install_web_deps += out_file
  install_web_files += '@0@:@1@'.format(out_file.full_path(), docs_html_dir)
endforeach

subdir('fonts')
subdir('html')
subdir('internals')
subdir('js')
subdir('kbase')
subdir('logos')
subdir('manpages')
subdir('schemas')


foreach file : docs_assets
  # This hack enables us to view the web pages
  # from within the uninstalled build tree
  configure_file(input: file, output: file, copy: true)

  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir)
endforeach

run_target(
  'install-web',
  command: [
    meson_python_prog, python3_prog.path(), meson_install_web_prog.path(),
    install_web_files,
  ],
  depends: install_web_deps,
)
