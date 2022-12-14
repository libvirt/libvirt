subdir('rpcgen')

if pytest_prog.found()
    subdir('tests')

    test(
        'rpcgen-pytest',
        python3_prog,
        args: [ '-mpytest' ] + rpcgen_tests,
        env: runutf8,
        workdir: meson.current_source_dir(),
    )
endif

rpcgen_prog = find_program('main.py')
rpcgen_src += files(['main.py'])
