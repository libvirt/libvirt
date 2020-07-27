apparmor_gen_profiles = [
  'usr.lib.libvirt.virt-aa-helper',
  'usr.sbin.libvirtd',
]

apparmor_gen_profiles_conf = configuration_data()
apparmor_gen_profiles_conf.set('sysconfdir', sysconfdir)
apparmor_gen_profiles_conf.set('sbindir', sbindir)
apparmor_gen_profiles_conf.set('runstatedir', runstatedir)
apparmor_gen_profiles_conf.set('libexecdir', libexecdir)

apparmor_dir = sysconfdir / 'apparmor.d'

foreach name : apparmor_gen_profiles
  configure_file(
    input: '@0@.in'.format(name),
    output: name,
    configuration: apparmor_gen_profiles_conf,
    install: true,
    install_dir: apparmor_dir,
  )
endforeach

install_data(
  [ 'libvirt-qemu', 'libvirt-lxc' ],
  install_dir: apparmor_dir / 'abstractions',
)

install_data(
  [ 'TEMPLATE.qemu', 'TEMPLATE.lxc' ],
  install_dir: apparmor_dir / 'libvirt',
)

install_data(
  'usr.lib.libvirt.virt-aa-helper.local',
  install_dir: apparmor_dir / 'local',
  rename: 'usr.lib.libvirt.virt-aa-helper',
)
