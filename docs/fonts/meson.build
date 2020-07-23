fonts = [
  'LICENSE.rst',
  'stylesheet.css',
  'overpass-bold-italic.woff',
  'overpass-bold.woff',
  'overpass-italic.woff',
  'overpass-light-italic.woff',
  'overpass-light.woff',
  'overpass-mono-bold.woff',
  'overpass-mono-light.woff',
  'overpass-mono-regular.woff',
  'overpass-mono-semibold.woff',
  'overpass-regular.woff',
]

install_data(fonts, install_dir: docs_html_dir / 'fonts')

foreach file : fonts
  # This hack enables us to view the web pages
  # from within the uninstalled build tree
  configure_file(input: file, output: file, copy: true)

  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir / 'fonts')
endforeach
