syntax_check_conf = configuration_data()
syntax_check_conf.set('top_srcdir', meson.source_root())
syntax_check_conf.set('top_builddir', meson.build_root())

flake8_path = ''
if flake8_prog.found()
  flake8_path = flake8_prog.path()
endif
syntax_check_conf.set('flake8_path', flake8_path)
syntax_check_conf.set('runutf8', ' '.join(runutf8))
syntax_check_conf.set('PYTHON3', python3_prog.path())

configure_file(
  input: 'Makefile.in',
  output: '@BASENAME@',
  configuration: syntax_check_conf,
)

if host_machine.system() == 'freebsd'
  make_prog = find_program('gmake')
else
  make_prog = find_program('make')
endif

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
