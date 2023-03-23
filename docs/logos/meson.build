docs_logo_files = [
  'logo-banner-dark-256.png',
  'logo-banner-dark-800.png',
  'logo-banner-dark.svg',
  'logo-banner-light-256.png',
  'logo-banner-light-800.png',
  'logo-banner-light.svg',
  'logo-base.svg',
  'logo-square-128.png',
  'logo-square-192.png',
  'logo-square-256.png',
  'logo-square-96.png',
  'logo-square-powered-128.png',
  'logo-square-powered-192.png',
  'logo-square-powered-256.png',
  'logo-square-powered-96.png',
  'logo-square-powered.svg',
  'logo-square.svg',
  'logo-sticker-hexagon.svg',
  'logo-sticker-square.svg',
]

install_data(docs_logo_files, install_dir: docs_html_dir / 'logos')

foreach file : docs_logo_files
  # This hack enables us to view the web pages
  # from within the uninstalled build tree
  if meson.version().version_compare('>=0.64.0')
    fs.copyfile(file)
  else
    configure_file(input: file, output: file, copy: true)
  endif

  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir / 'logos')
endforeach


html_xslt_gen_install_dir = docs_html_dir / 'logos'
html_xslt_gen = []

# README.rst is formatted as index.html for viewing
html_xslt_gen += {
  'name': 'index',
  'file': docs_rst2html5_gen.process('README.rst'),
  'source': 'docs' / 'logos' / 'README.rst',
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
