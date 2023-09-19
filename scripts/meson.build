scripts = [
  'apibuild.py',
  'augeas-gentest.py',
  'check-aclperms.py',
  'check-aclrules.py',
  'check-driverimpls.py',
  'check-drivername.py',
  'check-file-access.py',
  'check-html-references.py',
  'check-remote-protocol.py',
  'check-symfile.py',
  'check-symsorting.py',
  'dtrace2systemtap.py',
  'esx_vi_generator.py',
  'genaclperms.py',
  'genpolkit.py',
  'gensystemtap.py',
  'group-qemu-caps.py',
  'header-ifdef.py',
  'hvsupport.py',
  'hyperv_wmi_generator.py',
  'merge-systemd-units.py',
  'meson-dist.py',
  'meson-gen-authors.py',
  'meson-gen-def.py',
  'meson-gen-sym.py',
  'meson-install-dirs.py',
  'meson-install-symlink.py',
  'meson-install-web.py',
  'meson-python.sh',
  'meson-timestamp.py',
  'mock-noinline.py',
  'prohibit-duplicate-header.py',
]

foreach name : scripts
  sname = name.split('.')[0].underscorify()
  set_variable('@0@_prog'.format(sname), find_program(name))
endforeach
