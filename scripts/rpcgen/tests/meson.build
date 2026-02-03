rpcgen_tests = files([
  'test_generator.py',
  'test_lexer.py',
  'test_parser.py',
])

xdrproc_flags = []
if conf.has('XDRPROC_T_3ARGS')
  xdrproc_flags += [ '-DXDRPROC_T_3ARGS' ]
endif

test_demo = executable(
  'test_demo',
  [ 'test_demo.c' ],
  c_args: [
    '-Dabs_srcdir="@0@"'.format(meson.current_source_dir()),
  ] + cc_flags_relaxed_frame_limit + xdrproc_flags,
  dependencies: [
    xdr_dep, glib_dep
  ],
)

test(
  'test_demo',
  test_demo,
  workdir: meson.current_source_dir(),
  suite: 'bin',
)
