docs_js_files = [
  'main.js',
]

install_data(docs_js_files, install_dir: docs_html_dir / 'js')

foreach file : docs_js_files
  # This hack enables us to view the web pages
  # from within the uninstalled build tree
  if meson.version().version_compare('>=0.64.0')
    fs.copyfile(file)
  else
    configure_file(input: file, output: file, copy: true)
  endif

  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir / 'js')
endforeach
