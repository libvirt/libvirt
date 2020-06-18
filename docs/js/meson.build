docs_js_files = [
  'main.js',
]

install_data(docs_js_files, install_dir: docs_html_dir / 'js')

# This hack enables us to view the web pages
# from within the uninstalled build tree
foreach file : docs_js_files
  configure_file(input: file, output: file, copy: true)
endforeach
