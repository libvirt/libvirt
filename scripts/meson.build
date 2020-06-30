scripts = [
  'apibuild.py',
  'augeas-gentest.py',
  'check-aclperms.py',
  'check-aclrules.py',
  'check-driverimpls.py',
  'check-drivername.py',
  'check-file-access.py',
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
  'meson-python.sh',
  'mock-noinline.py',
  'prohibit-duplicate-header.py',
  'test-wrap-argv.py',
]

foreach name : scripts
  sname = name.split('.')[0].underscorify()
  set_variable('@0@_prog'.format(sname), find_program(name))
endforeach
