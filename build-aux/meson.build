flake8_path = ''
if flake8_prog.found()
  flake8_path = flake8_prog.path()
endif

if host_machine.system() == 'freebsd' or host_machine.system() == 'darwin'
  make_prog = find_program('gmake')
  sed_prog = find_program('gsed')
else
  make_prog = find_program('make')
  sed_prog = find_program('sed')
endif

if host_machine.system() == 'freebsd'
  grep_prog = find_program('grep')
  grep_cmd = run_command(grep_prog, '--version', check: true)
  if grep_cmd.stdout().startswith('grep (BSD grep')
    grep_prog = find_program('/usr/local/bin/grep', required: false)
    if not grep_prog.found()
      error('GNU grep not found')
    endif
  endif
elif host_machine.system() == 'darwin'
  grep_prog = find_program('ggrep')
else
  grep_prog = find_program('grep')
endif

syntax_check_conf = configuration_data({
  'top_srcdir': meson.source_root(),
  'top_builddir': meson.build_root(),
  'flake8_path': flake8_path,
  'runutf8': ' '.join(runutf8),
  'PYTHON3': python3_prog.path(),
  'GREP': grep_prog.path(),
  'SED': sed_prog.path(),
})

configure_file(
  input: 'Makefile.in',
  output: '@BASENAME@',
  configuration: syntax_check_conf,
)

rc = run_command(
  'sed', '-n',
  's/^\\(sc_[a-zA-Z0-9_-]*\\):.*/\\1/p',
  meson.current_source_dir() / 'syntax-check.mk',
  check: true,
)

sc_tests = rc.stdout().strip().split()


# Skip syntax-check if not building from git because we get the list of files
# to check using git commands and it fails if we are not in git repository.
if git
  foreach target : sc_tests
    test(
      target,
      make_prog,
      args: [ '-C', meson.current_build_dir(), target ],
      depends: [
        potfiles_dep,
      ],
      suite: 'syntax-check',
    )
  endforeach
endif
