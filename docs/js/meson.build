docs_js_files = [
  'main.js',
]

install_data(docs_js_files, install_dir: docs_html_dir / 'js')

foreach file : docs_js_files
  # This hack enables us to view the web pages
  # from within the uninstalled build tree
  configure_file(input: file, output: file, copy: true)

    install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir / 'js')
endforeach
