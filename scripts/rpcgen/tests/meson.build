rpcgen_tests = files([
  'test_generator.py',
  'test_lexer.py',
  'test_parser.py',
])


test_demo = executable(
  'test_demo',
  [ 'test_demo.c' ],
  c_args: [
    '-Dabs_srcdir="@0@"'.format(meson.current_source_dir()),
  ] + cc_flags_relaxed_frame_limit,
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
