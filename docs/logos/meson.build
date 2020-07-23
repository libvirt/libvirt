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
  configure_file(input: file, output: file, copy: true)

  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir / 'logos')
endforeach
