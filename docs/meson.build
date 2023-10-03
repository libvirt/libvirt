docs_html_dir = docdir / 'html'

# xsltproc requires that the -o path ends with '/'
# Not using '/' operator due to bug in meson 0.60.0
# https://github.com/mesonbuild/meson/issues/9450
docs_builddir = join_paths(meson.current_build_dir(), '')

docs_assets = [
  'android-chrome-192x192.png',
  'android-chrome-256x256.png',
  'apple-touch-icon.png',
  'browserconfig.xml',
  'favicon.ico',
  'favicon-16x16.png',
  'favicon-32x32.png',
  'manifest.json',
  'mstile-150x150.png',
]

docs_rst_files = [
  'aclpolkit',
  'advanced-tests',
  'api',
  'api_extension',
  'apps',
  'auditlog',
  'auth',
  'best-practices',
  'bindings',
  'bugs',
  'cgroups',
  'ci',
  'ci-dashboard',
  'ci-runners',
  'clangd',
  'coding-style',
  'committer-guidelines',
  'compiling',
  'contact',
  'contribute',
  'csharp',
  'daemons',
  'dbus',
  'docs',
  'downloads',
  'drivers',
  'drvbhyve',
  'drvch',
  'drvesx',
  'drvhyperv',
  'drvlxc',
  'drvnodedev',
  'drvopenvz',
  'drvqemu',
  'drvsecret',
  'drvtest',
  'drvvbox',
  'drvvirtuozzo',
  'drvvmware',
  'drvxen',
  'errors',
  'firewall',
  'format',
  'formatbackup',
  'formatcaps',
  'formatcheckpoint',
  'formatdomain',
  'formatdomaincaps',
  'formatnetwork',
  'formatnetworkport',
  'formatnode',
  'formatnwfilter',
  'formatsecret',
  'formatsnapshot',
  'formatstorage',
  'formatstoragecaps',
  'formatstorageencryption',
  'glib-adoption',
  'goals',
  'golang',
  'governance',
  'hacking',
  'hooks',
  'index',
  'issue-handling',
  'libvirt-go',
  'libvirt-go-xml',
  'logging',
  'macos',
  'migration',
  'newreposetup',
  'nss',
  'pci-addresses',
  'pci-hotplug',
  'platforms',
  'programming-languages',
  'python',
  'remote',
  'securityprocess',
  'storage',
  'strategy',
  'styleguide',
  'submitting-patches',
  'support',
  'testapi',
  'testing',
  'testtck',
  'uri',
  'windows',
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
    genaclperms_prog, '@INPUT@',
  ],
  capture: true,
)

docs_timestamp = run_command(
  python3_prog, meson_timestamp_prog.full_path(), env: runutf8, check: true,
).stdout().strip()

site_xsl = files('site.xsl')
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
    apibuild_prog,
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
    meson.project_source_root() / 'src' / 'remote' / 'remote_protocol.x',
    meson.project_source_root() / 'src' / 'remote' / 'qemu_protocol.x',
    meson.project_source_root() / 'src' / 'remote' / 'lxc_protocol.x',
  ],
)

docs_api_xml = docs_api_generated[0]
docs_lxc_api_xml = docs_api_generated[1]
docs_qemu_api_xml = docs_api_generated[2]
docs_admin_api_xml = docs_api_generated[3]

docs_programs_groups = [
  { 'name': 'rst2html5', 'prog': [ 'rst2html5', 'rst2html5.py', 'rst2html5-3' ] },
  { 'name': 'rst2man', 'prog': [ 'rst2man', 'rst2man.py', 'rst2man-3' ] },
]

foreach item : docs_programs_groups
  prog = find_program(item.get('prog'), dirs: libvirt_sbin_path)
  varname = item.get('name').underscorify()
  conf.set_quoted(varname.to_upper(), prog.full_path())
  set_variable('@0@_prog'.format(varname), prog)
endforeach

# There are two versions of rst2html5 in the wild: one is the version
# coming from the docutils package, and the other is the one coming
# from the rst2html5 package. These versions are subtly different,
# and the libvirt documentation can only be successfully generated
# using the docutils version. Every now and then, users will report
# build failures that can be traced back to having the wrong version
# installed.
#
# The only reliable way to tell the two binaries apart seems to be
# looking look at their version information: the docutils version
# will report
#
#   rst2html5 (Docutils ..., Python ..., on ...)
#
# whereas the rst2html5 version will report
#
#   rst2html5 ... (Docutils ..., Python ..., on ...)
#
# with the additional bit of information being the version number for
# the rst2html5 package itself.
#
# Use this knowledge to detect the version that we know doesn't work
# for building libvirt and reject it
rst2html5_version = run_command(rst2html5_prog, '--version', check: true)
rst2html5_version = rst2html5_version.stdout().split(' ')
if rst2html5_version[1] != '(Docutils'
  error('Please uninstall the rst2html5 package and install the docutils package')
endif

docs_rst2html5_gen = generator(
  rst2html5_prog,
  output: '@BASENAME@.html.in',
  arguments: [ '--exit-status=1', '--stylesheet=', '--strict', '@INPUT@' ],
  capture: true,
)


# html_xslt_gen config

html_xslt_gen_install_dir = docs_html_dir

html_xslt_gen = []
# html_xslt_gen:
#   each entry is a dictionary with following items:
#   name - base file name (required), output file will become 'name.html'
#   file - input file (optional, 'name.html.in' assumed if missing)
# source - source filename relative to repository root (optional, if there is no source)
# depends - explicit dependency on other input (optional)

foreach name : docs_rst_files
  rst_file = '@0@.rst'.format(name)
  html_xslt_gen += {
    'name': name,
    'file': docs_rst2html5_gen.process(rst_file),
    'source': 'docs' / rst_file,
  }
endforeach

html_xslt_gen += {
  'name': 'acl',
  'file': docs_rst2html5_gen.process('acl.rst'),
  'source': 'docs' / 'acl.rst',
  'depends': aclperms_gen,
}

html_xslt_gen += {
  'name': '404',
  'file': docs_rst2html5_gen.process('404.rst'),
  'source': 'docs' / '404.rst',
  'href_base': '/',
}

hvsupport_html_in = custom_target(
  'hvsupport.html.in',
  output: 'hvsupport.html.in',
  command: [
    hvsupport_prog,
    meson.project_source_root(),
    meson.project_build_root(),
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

news_html_in = docs_rst2html5_gen.process(meson.project_source_root() / 'NEWS.rst')
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

subdir('css')
subdir('fonts')
subdir('go')
subdir('html')
subdir('images')
subdir('js')
subdir('kbase')
subdir('logos')
subdir('manpages')

foreach file : docs_assets
  # This hack enables us to view the web pages
  # from within the uninstalled build tree
  if meson.version().version_compare('>=0.64.0')
    fs.copyfile(file)
  else
    configure_file(input: file, output: file, copy: true)
  endif

  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir)
endforeach

run_target(
  'install-web',
  command: [
    meson_python_prog, python3_prog.full_path(), meson_install_web_prog.full_path(),
    install_web_files,
  ],
  depends: install_web_deps,
)

if tests_enabled[0]
  test(
    'check-html-references',
    python3_prog,
    args: [
      check_html_references_prog.full_path(),
      '--webroot',
      meson.project_build_root() / 'docs'
    ],
    env: runutf8,
    suite: 'script'
  )
endif
