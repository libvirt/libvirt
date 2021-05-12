docs_html_dir = docdir / 'html'

# xsltproc requires that the -o path ends with '/'
docs_builddir = meson.current_build_dir() / ''

docs_assets = [
  'android-chrome-192x192.png',
  'android-chrome-256x256.png',
  'apple-touch-icon.png',
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
  'bugs',
  'cgroups',
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
  'aclpolkit',
  'advanced-tests',
  'api_extension',
  'api',
  'apps',
  'auditlog',
  'auth',
  'bindings',
  'best-practices',
  'ci',
  'coding-style',
  'committer-guidelines',
  'compiling',
  'daemons',
  'developer-tooling',
  'drvqemu',
  'drvch',
  'formatbackup',
  'formatcheckpoint',
  'formatdomain',
  'glib-adoption',
  'hacking',
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
    meson_python_prog, python3_prog, genaclperms_prog, '@INPUT@',
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
    meson_python_prog, python3_prog, apibuild_prog,
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


# html_xslt_gen config

html_xslt_gen_xslt = site_xsl
html_xslt_gen_install_dir = docs_html_dir

html_xslt_gen = []
# html_xslt_gen:
#   each entry is a dictionary with following items:
#   name - base file name (required), output file will become 'name.html'
#   file - input file (optional, 'name.html.in' assumed if missing)
# source - source filename relative to repository root (optional, if there is no source)
# depends - explicit dependency on other input (optional)

foreach name : docs_html_in_files
  html_xslt_gen += {
    'name': name,
    'source': 'docs' / name + '.html.in',
  }
endforeach

foreach name : docs_rst_files
  rst_file = '@0@.rst'.format(name)
  html_xslt_gen += {
    'name': name,
    'file': docs_rst2html_gen.process(rst_file),
    'source': 'docs' / rst_file,
  }
endforeach

html_xslt_gen += {
  'name': 'acl',
  'source': 'docs' / 'acl.html.in',
  'depends': aclperms_gen,
}

hvsupport_html_in = custom_target(
  'hvsupport.html.in',
  output: 'hvsupport.html.in',
  command: [
    meson_python_prog,
    python3_prog,
    hvsupport_prog,
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
html_xslt_gen += {
  'name': 'hvsupport',
  'file': hvsupport_html_in,
}

news_html_in = docs_rst2html_gen.process(meson.source_root() / 'NEWS.rst')
html_xslt_gen += {
  'name': 'news',
  'file': news_html_in,
  'source': 'NEWS.rst',
}

# The following code between the markers must be kept identical with the other
# copies of the code in various subdirs, since meson doesn't support any kind
# of functions.

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
      '--stringparam', 'builddir', meson.build_root(),
      '--stringparam', 'timestamp', docs_timestamp,
      '--nonet',
      html_xslt_gen_xslt,
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
