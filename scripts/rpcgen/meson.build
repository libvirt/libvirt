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
