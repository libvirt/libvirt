libvirt_common_h_in = files('libvirt-common.h.in')

libvirt_include = files(
  'libvirt-admin.h',
  'libvirt-domain-checkpoint.h',
  'libvirt-domain.h',
  'libvirt-domain-snapshot.h',
  'libvirt-event.h',
  'libvirt.h',
  'libvirt-host.h',
  'libvirt-interface.h',
  'libvirt-lxc.h',
  'libvirt-network.h',
  'libvirt-nodedev.h',
  'libvirt-nwfilter.h',
  'libvirt-qemu.h',
  'libvirt-secret.h',
  'libvirt-storage.h',
  'libvirt-stream.h',
  'virterror.h',
)

include_conf = configuration_data()
include_conf.merge_from(conf)

libvirt_common_h = configure_file(
  input: libvirt_common_h_in,
  output: '@BASENAME@',
  configuration: include_conf,
)

install_headers(
  libvirt_include,
  libvirt_common_h,
  install_dir: includedir / 'libvirt',
)
