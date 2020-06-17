project(
    'libvirt', 'c',
    version: '6.7.0',
    license: 'LGPLv2+',
    meson_version: '>= 0.54.0',
    default_options: [
        'buildtype=debugoptimized',
        'b_pie=true',
        'c_std=gnu99',
        'warning_level=2',
    ],
)


if not get_option('force_incomplete_build')
  error('This commit is part of the meson conversion and does not build a complete libvirt. If bisecting, use "git bisect skip" to continue, or "-Dforce_incomplete_build=true" to perform a partial build.')
endif


# figure out if we are building from git

git = run_command('test', '-d', '.git').returncode() == 0

if git and not get_option('no_git')
  run_command('git', 'submodule', 'update', '--init')
endif


# prepare build configuration data

conf = configuration_data()

conf.set('_GNU_SOURCE', 1)
conf.set_quoted('abs_top_builddir', meson.build_root())
conf.set_quoted('abs_top_srcdir', meson.source_root())
conf.set_quoted('PACKAGE', meson.project_name())
conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('VERSION', meson.project_version())

if host_machine.system() == 'windows'
  # For AI_ADDRCONFIG
  conf.set('_WIN32_WINNT', '0x0600') # Win Vista / Server 2008
  conf.set('WINVER', '0x0600') # Win Vista / Server 2008
endif


# set various paths

if get_option('system')
  prefix = '/usr'
  libdir = prefix / 'lib64'
  if run_command('test', '-d', libdir).returncode() != 0
    libdir = prefix / 'lib'
  endif
  localstatedir = '/var'
  sysconfdir = '/etc'
else
  prefix = get_option('prefix')
  libdir = prefix / get_option('libdir')
  localstatedir = prefix / get_option('localstatedir')
  sysconfdir = prefix / get_option('sysconfdir')
endif

# if --prefix is /usr, don't use /usr/var for localstatedir or /usr/etc for
# sysconfdir as this makes a lot of things break in testing situations
if prefix == '/usr'
  if localstatedir == '/usr/var'
    localstatedir = '/var'
  endif
  if sysconfdir == '/usr/etc'
    sysconfdir = '/etc'
  endif
endif

runstatedir = get_option('runstatedir')
if runstatedir == ''
  runstatedir = localstatedir / 'run'
endif

bindir = prefix / get_option('bindir')
datadir = prefix / get_option('datadir')
includedir = prefix / get_option('includedir')
infodir = prefix / get_option('infodir')
libexecdir = prefix / get_option('libexecdir')
localedir = prefix / get_option('localedir')
mandir = prefix / get_option('mandir')
sbindir = prefix / get_option('sbindir')
sharedstatedir = prefix / get_option('sharedstatedir')

confdir = sysconfdir / meson.project_name()
docdir = datadir / 'doc' / meson.project_name()
pkgdatadir = datadir / meson.project_name()


# generate configmake.h header

configmake_conf = configuration_data()
configmake_conf.set_quoted('BINDIR', bindir)
configmake_conf.set_quoted('DATADIR', datadir)
configmake_conf.set_quoted('LIBDIR', libdir)
configmake_conf.set_quoted('LIBEXECDIR', libexecdir)
configmake_conf.set_quoted('LOCALEDIR', localedir)
configmake_conf.set_quoted('LOCALSTATEDIR', localstatedir)
configmake_conf.set_quoted('MANDIR', mandir)
configmake_conf.set_quoted('PKGDATADIR', pkgdatadir)
configmake_conf.set_quoted('PREFIX', prefix)
configmake_conf.set_quoted('RUNSTATEDIR', runstatedir)
configmake_conf.set_quoted('SBINDIR', sbindir)
configmake_conf.set_quoted('SYSCONFDIR', sysconfdir)

configure_file(
  input: 'configmake.h.in',
  output: 'configmake.h',
  configuration: configmake_conf,
)


# packager options

packager = get_option('packager')
packager_version = get_option('packager_version')

if packager != ''
  conf.set_quoted('PACKAGER', packager)
endif

if packager_version != ''
  conf.set_quoted('PACKAGER_VERSION', packager_version)
endif


# test options

if get_option('expensive_tests').auto()
  use_expensive_tests = not git
else
  use_expensive_tests = get_option('expensive_tests').enabled()
endif

coverage_flags = []
if get_option('test_coverage')
  coverage_flags = [
    '-fprofile-arcs',
    '-ftest-coverage',
  ]
endif


# Detect when running under the clang static analyzer's scan-build driver
# or Coverity-prevent's cov-build. Define STATIC_ANALYSIS accordingly.

rc = run_command(
  'sh', '-c',
  'test -n "${CCC_ANALYZER_HTML}"' +
    ' -o -n "${CCC_ANALYZER_ANALYSIS+set}"' +
    ' -o -n "$COVERITY_BUILD_COMMAND$COVERITY_LD_PRELOAD"',
)
if rc.returncode() == 0
  conf.set('STATIC_ANALYSIS', 1)
endif


# figure out libvirt version strings

arr_version = meson.project_version().split('.')
libvirt_version_number = 1000000 * arr_version[0].to_int() + 1000 * arr_version[1].to_int() + arr_version[2].to_int()

conf.set('LIBVIRT_VERSION_NUMBER', libvirt_version_number)

# In libtool terminology we need to figure out:
#
# CURRENT
#     The most recent interface number that this library implements.
#
# REVISION
#     The implementation number of the CURRENT interface.
#
# AGE
#     The difference between the newest and oldest interfaces that this
#     library implements.
#
# In other words, the library implements all the interface numbers
# in the range from number `CURRENT - AGE' to `CURRENT'.
#
# Libtool assigns the soname version from `CURRENT - AGE', and we
# don't want that to ever change in libvirt. ie it must always be
# zero, to produce libvirt.so.0.
#
# We would, however, like the libvirt version number reflected
# in the so version'd symlinks, and this is based on AGE.REVISION
# eg  libvirt.so.0.AGE.REVISION
#
# The following examples show what libtool will do
#
# Input: 0.9.14 ->   libvirt.so.0.9.14
# Input: 1.0.0  ->   libvirt.so.0.1000.0
# Input: 2.5.8  ->   libvirt.so.0.2005.8
#
# Assuming we do ever want to break soname version, this can
# toggled. But seriously, don't ever touch this.

libvirt_so_version = 0
libvirt_age = 1000 * arr_version[0].to_int() + arr_version[1].to_int()
libvirt_revision = arr_version[2].to_int()
libvirt_lib_version = '@0@.@1@.@2@'.format(libvirt_so_version, libvirt_age, libvirt_revision)


# check compile flags

cc = meson.get_compiler('c')
cc_flags = []

git_werror = get_option('git_werror')
if git_werror.enabled() or git_werror.auto() and git
  cc_flags += [ '-Werror' ]
endif

cc_flags += [
  '-fno-common',
  '-W',
  '-Wabsolute-value',
  '-Waddress',
  '-Waddress-of-packed-member',
  '-Waggressive-loop-optimizations',
  '-Wattribute-warning',
  '-Wattributes',
  '-Wbool-compare',
  '-Wbool-operation',
  '-Wbuiltin-declaration-mismatch',
  '-Wbuiltin-macro-redefined',
  '-Wcannot-profile',
  '-Wcast-align',
  '-Wcast-align=strict',
  '-Wcast-function-type',
  '-Wchar-subscripts',
  '-Wclobbered',
  '-Wcomment',
  '-Wcomments',
  '-Wcoverage-mismatch',
  '-Wcpp',
  '-Wdangling-else',
  '-Wdate-time',
  '-Wdeprecated-declarations',
  '-Wdesignated-init',
  '-Wdiscarded-array-qualifiers',
  '-Wdiscarded-qualifiers',
  '-Wdiv-by-zero',
  '-Wduplicated-cond',
  '-Wduplicate-decl-specifier',
  '-Wempty-body',
  '-Wendif-labels',
  '-Wexpansion-to-defined',
  '-Wformat-contains-nul',
  '-Wformat-extra-args',
  '-Wformat-nonliteral',
  '-Wformat-security',
  '-Wformat-y2k',
  '-Wformat-zero-length',
  '-Wframe-address',
  '-Wfree-nonheap-object',
  '-Whsa',
  '-Wif-not-aligned',
  '-Wignored-attributes',
  '-Wignored-qualifiers',
  '-Wimplicit',
  '-Wimplicit-function-declaration',
  '-Wimplicit-int',
  '-Wincompatible-pointer-types',
  '-Winit-self',
  '-Winline',
  '-Wint-conversion',
  '-Wint-in-bool-context',
  '-Wint-to-pointer-cast',
  '-Winvalid-memory-model',
  '-Winvalid-pch',
  '-Wlogical-not-parentheses',
  '-Wlogical-op',
  '-Wmain',
  '-Wmaybe-uninitialized',
  '-Wmemset-elt-size',
  '-Wmemset-transposed-args',
  '-Wmisleading-indentation',
  '-Wmissing-attributes',
  '-Wmissing-braces',
  '-Wmissing-declarations',
  '-Wmissing-field-initializers',
  '-Wmissing-include-dirs',
  '-Wmissing-parameter-type',
  '-Wmissing-profile',
  '-Wmissing-prototypes',
  '-Wmultichar',
  '-Wmultistatement-macros',
  '-Wnarrowing',
  '-Wnested-externs',
  '-Wnonnull',
  '-Wnonnull-compare',
  '-Wnull-dereference',
  '-Wodr',
  '-Wold-style-declaration',
  '-Wold-style-definition',
  '-Wopenmp-simd',
  '-Woverflow',
  '-Woverride-init',
  '-Wpacked-bitfield-compat',
  '-Wpacked-not-aligned',
  '-Wparentheses',
  '-Wpointer-arith',
  '-Wpointer-compare',
  '-Wpointer-sign',
  '-Wpointer-to-int-cast',
  '-Wpragmas',
  '-Wpsabi',
  '-Wrestrict',
  '-Wreturn-local-addr',
  '-Wreturn-type',
  '-Wscalar-storage-order',
  '-Wsequence-point',
  '-Wshadow',
  '-Wshift-count-negative',
  '-Wshift-count-overflow',
  '-Wshift-negative-value',
  '-Wsizeof-array-argument',
  '-Wsizeof-pointer-div',
  '-Wsizeof-pointer-memaccess',
  '-Wstrict-aliasing',
  '-Wstrict-prototypes',
  '-Wstringop-truncation',
  '-Wsuggest-attribute=cold',
  '-Wsuggest-attribute=const',
  '-Wsuggest-attribute=format',
  '-Wsuggest-attribute=noreturn',
  '-Wsuggest-attribute=pure',
  '-Wsuggest-final-methods',
  '-Wsuggest-final-types',
  '-Wswitch',
  '-Wswitch-bool',
  '-Wswitch-unreachable',
  '-Wsync-nand',
  '-Wtautological-compare',
  '-Wtrampolines',
  '-Wtrigraphs',
  '-Wtype-limits',
  '-Wuninitialized',
  '-Wunknown-pragmas',
  '-Wunused',
  '-Wunused-but-set-parameter',
  '-Wunused-but-set-variable',
  '-Wunused-function',
  '-Wunused-label',
  '-Wunused-local-typedefs',
  '-Wunused-parameter',
  '-Wunused-result',
  '-Wunused-value',
  '-Wunused-variable',
  '-Wvarargs',
  '-Wvariadic-macros',
  '-Wvector-operation-performance',
  '-Wvla',
  '-Wvolatile-register-var',
  '-Wwrite-strings',
]

# gcc --help=warnings outputs
ptrdiff_max = cc.sizeof('ptrdiff_t', prefix: '#include <stddef.h>')
size_max = cc.sizeof('size_t', prefix: '#include <stdint.h>')
# Compute max safe object size by checking ptrdiff_t and size_t sizes.
# Ideally we would get PTRDIFF_MAX and SIZE_MAX values but it would
# give us (2147483647L) and we would have to remove the () and the suffix
# in order to convert it to numbers to be able to pick the smaller one.
alloc_max = run_command(
  'python3', '-c',
  'print(min(2**(@0@ * 8 - 1) - 1, 2**(@1@ * 8) - 1))'.format(ptrdiff_max, size_max),
)
cc_flags += [
  '-Walloc-size-larger-than=@0@'.format(alloc_max.stdout().strip()),
  '-Warray-bounds=2',
  '-Wattribute-alias=2',
  '-Wformat-overflow=2',
  '-Wformat-truncation=2',
  '-Wimplicit-fallthrough=5',
  '-Wnormalized=nfc',
  '-Wshift-overflow=2',
  '-Wstringop-overflow=2',
  '-Wunused-const-variable=2',
  '-Wvla-larger-then=4031',
]

cc_flags += [
  # So we have -W enabled, and then have to explicitly turn off...
  '-Wno-sign-compare',

  # We do "bad" function casts all the time for event callbacks
  '-Wno-cast-function-type',

  # CLang incorrectly complains about dup typedefs win gnu99 mode
  # so use this CLang-specific arg to keep it quiet
  '-Wno-typedef-redefinition',

  # We don't use -Wc++-compat so we have to enable it explicitly
  '-Wjump-misses-init',

  # -Wswitch is enabled but that doesn't report missing enums if a default:
  # is present
  '-Wswitch-enum',

  # -Wformat=2 implies -Wformat-nonliteral so we need to manually exclude it
  '-Wno-format-nonliteral',

  # -Wformat enables this by default, and we should keep it,
  # but need to rewrite various areas of code first
  '-Wno-format-truncation',

  # This should be < 256 really. Currently we're down to 4096,
  # but using 1024 bytes sized buffers (mostly for virStrerror)
  # stops us from going down further
  '-Wframe-larger-than=4096',

  # extra special flags
  '-fexceptions',
  '-fasynchronous-unwind-tables',

  # Need -fipa-pure-const in order to make -Wsuggest-attribute=pure
  # fire even without -O.
  '-fipa-pure-const',

  # We should eventually enable this, but right now there are at
  # least 75 functions triggering warnings.
  '-Wno-suggest-attribute=pure',
  '-Wno-suggest-attribute=const',
]

# on aarch64 error: -fstack-protector not supported for this target
if host_machine.cpu_family() != 'aarch64'
  if host_machine.system() in [ 'linux', 'freebsd', 'windows' ]
    # we prefer -fstack-protector-strong but fallback to -fstack-protector-all
    fstack_cflags = cc.first_supported_argument([
      '-fstack-protector-strong',
      '-fstack-protector-all',
    ])
    cc_flags += fstack_cflags

    # When building with mingw using -fstack-protector requires libssp library
    # which is included by using -fstack-protector with linker.
    if fstack_cflags.length() == 1 and host_machine.system() == 'windows'
      add_project_link_arguments(fstack_cflags, language: 'c')
    endif
  endif
endif

if cc.has_argument('-Wlogical-op')
  # Broken in 6.0 and later
  #     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=69602
  w_logical_op_args = ['-O2', '-Wlogical-op', '-Werror']
  w_logical_op_code = '''
    #define TEST1 1
    #define TEST2 TEST1

    int main(void) {
      int test = 0;
      return test == TEST1 || test == TEST2;
    }
  '''
  if not cc.compiles(w_logical_op_code, args: w_logical_op_args)
    conf.set('BROKEN_GCC_WLOGICALOP_EQUAL_EXPR', 1)
  endif
endif

# Check whether clang gives bogus warning for -Wdouble-promotion.
w_double_promotion_args = ['-O2', '-Wdouble-promotion', '-Werror']
w_double_promotion_code = '''
  #include <math.h>

  int main(void) {
    float f = 0.0;
    return isnan(f);
  }
'''
if cc.compiles(w_double_promotion_code, args: w_double_promotion_args, name: '-Wdouble-promotion')
  cc_flags += ['-Wdouble-promotion']
endif

# Clang complains about unused static inline functions which are common
# with G_DEFINE_AUTOPTR_CLEANUP_FUNC.
w_unused_function_args = ['-Wunused-function', '-Werror']
w_unused_function_code = '''
  static inline void foo(void) {}

  int main(void) { return 0; }
'''
# -Wunused-function is implied by -Wall, we must turn it off explicitly.
if not cc.compiles(w_unused_function_code, args: w_unused_function_args)
  cc_flags += ['-Wno-unused-function']
endif

cc_flags_disabled = [
  # In meson this is specified using 'c_std=gnu99' in project() function.
  '-std=gnu99',

  # In meson this is specified using 'warning_level=2' in project() function.
  '-Wall',
  '-Wextra',

  # don't care about C++ compiler compat
  '-Wc++-compat',
  '-Wabi',
  '-Wdeprecated',

  # Don't care about ancient C standard compat
  '-Wtraditional',
  '-Wtraditional-conversion',

  # Ignore warnings in /usr/include
  '-Wsystem-headers',

  # Happy for compiler to add struct padding
  '-Wpadded',

  # GCC very confused with -O2
  '-Wunreachable-code',

  # Too many to deal with
  '-Wconversion',
  '-Wsign-conversion',

  # Need to allow bad cast for execve()
  '-Wcast-qual',

  # We need to use long long in many places
  '-Wlong-long',

  # We allow manual list of all enum cases without default
  '-Wswitch-default',

  # Not a problem since we don't use -fstrict-overflow
  '-Wstrict-overflow',

  # Not a problem since we don't use -funsafe-loop-optimizations
  '-Wunsafe-loop-optimizations',

  # gcc 4.4.6 complains this is C++ only; gcc 4.7.0 implies this from -Wall
  '-Wenum-compare',

  # gcc 5.1 -Wformat-signedness mishandles enums, not ready for prime time
  '-Wformat-signedness',

  # Several conditionals expand the same on both branches depending on the
  # particular platform/architecture
  '-Wduplicated-branches',

  # > This warning does not generally indicate that there is anything wrong
  # > with your code; it merely indicates that GCC's optimizers are unable
  # > to handle the code effectively.
  # Source: https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
  '-Wdisabled-optimization',

  # Various valid glib APIs/macros trigger this warning
  '-Wbad-function-cast',

  # We might fundamentally need some of these disabled forever, but
  # ideally we'd turn many of them on
  '-Wfloat-equal',
  '-Wdeclaration-after-statement',
  '-Wpacked',
  '-Wunused-macros',
  '-Woverlength-strings',
  '-Wstack-protector',
  '-Wsuggest-attribute=malloc',
]

foreach flag : cc_flags_disabled
  if cc_flags.contains(flag)
    error('@0@ is disabled but listed in cc_flags'.format(flag))
  endif
endforeach

supported_cc_flags = cc.get_supported_arguments(cc_flags)
add_project_arguments(supported_cc_flags, language: 'c')

if cc.has_argument('-Wsuggest-attribute=format')
  conf.set('HAVE_SUGGEST_ATTRIBUTE_FORMAT', 1)
endif

# used in tests
cc_flags_relaxed_frame_limit = [
  '-Wframe-larger-than=262144',
]


# various linker checks

libvirt_relro = cc.get_supported_link_arguments([
  '-Wl,-z,relro',
  '-Wl,-z,now',
])

libvirt_nodelete = cc.get_supported_link_arguments([
  '-Wl,-z,nodelete',
])

libvirt_no_undefined = cc.get_supported_link_arguments([
  '-Wl,-z,defs',
])

libvirt_no_indirect = cc.get_supported_link_arguments([
  '-Wl,--no-copy-dt-needed-entries',
])

if host_machine.system() == 'windows'
  version_script_flags = '-Wl,'
else
  test_file = '@0@/src/libvirt_qemu.syms'.format(meson.source_root())
  if cc.has_link_argument('-Wl,--version-script=@0@'.format(test_file))
    version_script_flags = '-Wl,--version-script='
  elif cc.has_link_argument('-Wl,-M,')
    version_script_flags = '-Wl,-M,'
  else
    error('No supported version script link argument found.')
  endif
endif

libvirt_flat_namespace = []
if host_machine.system() == 'darwin'
  libvirt_flat_namespace = '-Wl,-flat_namespace'
endif

libvirt_export_dynamic = cc.first_supported_link_argument([
  '-Wl,-export-dynamic',
  '-Wl,-export_dynamic',
])


# define top include directory

top_inc_dir = include_directories('.')


# include remaining subdirs

subdir('scripts')


# generate meson-config.h file
configure_file(output: 'meson-config.h', configuration: conf)


# print configuration summary

test_summary = {
  'Coverage': coverage_flags.length() > 0,
}
summary(test_summary, section: 'Test suite', bool_yn: true)

misc_summary = {
  'Use -Werror': cc_flags.contains('-Werror'),
  'Warning Flags': supported_cc_flags,
}
summary(misc_summary, section: 'Miscellaneous', bool_yn: true, list_sep: ' ')
