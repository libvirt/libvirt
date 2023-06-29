apparmor_gen_profiles = [
  'usr.lib.libvirt.virt-aa-helper',
  'usr.sbin.libvirtd',
  'usr.sbin.virtqemud',
  'usr.sbin.virtxend',
]

apparmor_gen_abstractions = [
  'libvirt-qemu',
  'libvirt-lxc',
]

apparmor_gen_profiles_conf = configuration_data({
  'sysconfdir': sysconfdir,
  'sbindir': sbindir,
  'runstatedir': runstatedir,
  'libexecdir': libexecdir,
})

apparmor_dir = sysconfdir / 'apparmor.d'

# Our profiles use some features that only work well on AppArmor 3.x,
# specifically the 'include if exists' directive. In order to keep
# supporting AppArmor 2.x, the bits that are version-specific are
# enclosed in special markers and we decide which ones to include
# based on the AppArmor version detected on the host.
#
# TODO: drop the additional complexity once we no longer target
#       distros that ship AppArmor 2.x (Debian 11, Ubuntu 20.04)
if conf.has('WITH_APPARMOR_3')
  apparmor_gen_cmd = [
    'sed',
    '-e', '/[@]BEGIN_APPARMOR_3[@]/d',
    '-e', '/[@]END_APPARMOR_3[@]/d',
    '-e', '/[@]BEGIN_APPARMOR_2[@]/,/[@]END_APPARMOR_2[@]/d',
    '@INPUT@'
  ]
else
  apparmor_gen_cmd = [
    'sed',
    '-e', '/[@]BEGIN_APPARMOR_3[@]/,/[@]END_APPARMOR_3[@]/d',
    '-e', '/[@]BEGIN_APPARMOR_2[@]/d',
    '-e', '/[@]END_APPARMOR_2[@]/d',
    '@INPUT@'
  ]
endif

foreach name : apparmor_gen_profiles
  tmp = configure_file(
    input: '@0@.in'.format(name),
    output: '@0@.tmp'.format(name),
    command: apparmor_gen_cmd,
    capture: true,
  )
  configure_file(
    input: tmp,
    output: name,
    configuration: apparmor_gen_profiles_conf,
    install: true,
    install_dir: apparmor_dir,
  )
endforeach

foreach name : apparmor_gen_abstractions
  configure_file(
    input: '@0@.in'.format(name),
    output: name,
    command: apparmor_gen_cmd,
    capture: true,
    install: true,
    install_dir: apparmor_dir / 'abstractions',
  )
endforeach

install_data(
  [ 'TEMPLATE.qemu', 'TEMPLATE.lxc' ],
  install_dir: apparmor_dir / 'libvirt',
)

if not conf.has('WITH_APPARMOR_3')
  # We only install the empty local override for AppArmor 2.x. For
  # AppArmor 3.x, upstream's preference is to avoid creating these
  # files in order to limit the amount of filesystem clutter.
  install_data(
    'usr.lib.libvirt.virt-aa-helper.local',
    install_dir: apparmor_dir / 'local',
    rename: 'usr.lib.libvirt.virt-aa-helper',
  )
endif
