docs_go_files = [
  'libvirt',
  'libvirtxml',
]

html_xslt_gen_install_dir = docs_html_dir / 'go'
html_xslt_gen = []

foreach name : docs_go_files
  rst_file = '@0@.rst'.format(name)

  html_xslt_gen += {
    'name': name,
    'file': docs_rst2html5_gen.process(rst_file),
    'source': 'docs' / 'go' / rst_file,
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
