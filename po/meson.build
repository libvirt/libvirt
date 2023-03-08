i18n = import('i18n')

i18n.gettext(
  meson.project_name(),
  args: [
    '--from-code=UTF-8',
    '--keyword=_',
    '--keyword=N_',
    '--add-comments=TRANSLATORS:',
    '--directory=@0@'.format(meson.project_source_root()),
    '--directory=@0@'.format(meson.project_build_root()),
    '--files-from=@0@'.format(meson.current_source_dir() / 'POTFILES'),
    '--msgid-bugs-address=https://libvirt.org/bugs.html',
    '--package-version=@0@'.format(meson.project_version()),
    '--sort-output',
  ],
)

potfiles_dep = [
  access_gen_sources,
  admin_client_generated,
  admin_driver_generated,
  remote_driver_generated,
  remote_daemon_generated,
]

alias_target('libvirt-pot-dep', potfiles_dep)

run_target(
  'libvirt-pot-check',
  command: [
    '@0@/scripts/check-pot.py'.format(meson.project_source_root()),
    '@0@/po/libvirt.pot'.format(meson.project_source_root())
  ],
)
