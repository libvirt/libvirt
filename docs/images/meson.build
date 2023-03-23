docs_image_files = [
  'event_loop_simple.png',
  'event_loop_worker.png',
  'libvirt-daemon-arch.png',
  'libvirt-driver-arch.png',
  'libvirt-object-model.png',
  'libvirt-virConnect-example.png',
  'migration-managed-direct.png',
  'migration-managed-p2p.png',
  'migration-native.png',
  'migration-tunnel.png',
  'migration-unmanaged-direct.png',
]

install_data(docs_image_files, install_dir: docs_html_dir / 'images')

foreach file : docs_image_files
  # This hack enables us to view the web pages
  # from within the uninstalled build tree
  if meson.version().version_compare('>=0.64.0')
    fs.copyfile(file)
  else
    configure_file(input: file, output: file, copy: true)
  endif

  install_web_files += '@0@:@1@'.format(meson.current_source_dir() / file, docs_html_dir / 'images')
endforeach
