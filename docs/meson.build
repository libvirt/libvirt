docs_html_dir = docdir / 'html'

docs_assets = [
  'android-chrome-192x192.png',
  'android-chrome-256x256.png',
  'apple-touch-icon.png',
  'architecture.gif',
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

install_data(docs_assets, install_dir: docs_html_dir)

docs_api_generated = custom_target(
  'generate-api',
  output: [
    'libvirt-api.xml',
    'libvirt-lxc-api.xml',
    'libvirt-qemu-api.xml',
    'libvirt-admin-api.xml',
  ],
  command: [
    meson_python_prog, python3_prog.path(), apibuild_prog.path(),
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
