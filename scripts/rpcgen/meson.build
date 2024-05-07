subdir('rpcgen')

if tests_enabled[0] and xdr_dep.found()
  subdir('tests')

  if pytest_prog.found() and host_machine.system() != 'darwin'
    test(
      'rpcgen-pytest',
      python3_prog,
      args: [ '-mpytest' ] + rpcgen_tests,
      env: runutf8,
      workdir: meson.current_source_dir(),
      suite: 'script',
    )
  endif
endif

rpcgen_prog = find_program('main.py')
rpcgen_src += files(['main.py'])
