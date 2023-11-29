subdir('rpcgen')
subdir('tests')

if pytest_prog.found()
    test(
        'rpcgen-pytest',
        python3_prog,
        args: [ '-mpytest' ] + rpcgen_tests,
        env: runutf8,
        workdir: meson.current_source_dir(),
        suite: 'script',
    )
endif

rpcgen_prog = find_program('main.py')
rpcgen_src += files(['main.py'])
