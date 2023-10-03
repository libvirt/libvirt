project(
  'libvirt', 'c',
  version: '9.9.0',
  license: 'LGPLv2+',
  meson_version: '>= 0.56.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_pie=true',
    'c_std=gnu99',
    'warning_level=2',
  ],
)

if meson.version().version_compare('>=0.64.0')
  fs = import('fs')
endif

# figure out if we are building from git

git = run_command('test', '-d', '.git', check: false).returncode() == 0

if git and not get_option('no_git')
  run_command('git', 'submodule', 'update', '--init', check: true)
endif


# detect operating system

os_release = run_command('grep', '-E', '^ID(_LIKE)*=', '/etc/os-release', check: false).stdout()


# prepare build configuration data

conf = configuration_data()

conf.set('_GNU_SOURCE', 1)
conf.set_quoted('abs_top_builddir', meson.project_build_root())
conf.set_quoted('abs_top_srcdir', meson.project_source_root())
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
  if run_command('test', '-d', libdir, check: false).returncode() != 0
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

initconfdir = get_option('initconfdir')
if initconfdir == ''
  if (os_release.contains('alpine') or
      os_release.contains('arch') or
      os_release.contains('gentoo'))
    initconfdir = sysconfdir / 'conf.d'
  # Ubuntu has ID_LIKE=debian
  elif os_release.contains('debian')
    initconfdir = sysconfdir / 'default'
  else
    initconfdir = sysconfdir / 'sysconfig'
  endif
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

docdir = get_option('docdir')
if docdir == ''
  docdir = datadir / 'doc' / meson.project_name()
endif

confdir = sysconfdir / meson.project_name()
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
  output: '@BASENAME@',
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


# Add RPATH information when building for a non-standard prefix, or
# when explicitly requested to do so

if prefix == '/usr' and not get_option('rpath').enabled()
  libvirt_rpath = ''
else
  libvirt_rpath = libdir
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
if (git_werror.enabled() or git_werror.auto()) and git and not get_option('werror')
  cc_flags += [ '-Werror' ]
endif


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
  check: true,
)

stack_frame_size = 2048

# clang without optimization enlarges stack frames in certain corner cases
if cc.get_id() == 'clang' and get_option('optimization') == '0'
    stack_frame_size = 4096
endif

# sanitizer instrumentation may enlarge stack frames
if get_option('b_sanitize') != 'none'
  stack_frame_size = 32768
endif

# array_bounds=2 check triggers false positive on some GCC
# versions when using sanitizers. Seen on Fedora 34 with
# GCC 11.1.1
array_bounds = get_option('b_sanitize') == 'none' ? 2 : 1

cc_flags += [
  '-fasynchronous-unwind-tables',
  '-fexceptions',
  '-fipa-pure-const',
  '-fno-common',
  '-Wabsolute-value',
  '-Waddress',
  '-Waddress-of-packed-member',
  '-Waggressive-loop-optimizations',
  '-Walloc-size-larger-than=@0@'.format(alloc_max.stdout().strip()),
  '-Walloca',
  '-Warray-bounds=@0@'.format(array_bounds),
  '-Wattribute-alias=2',
  '-Wattribute-warning',
  '-Wattributes',
  '-Wbool-compare',
  '-Wbool-operation',
  '-Wbuiltin-declaration-mismatch',
  '-Wbuiltin-macro-redefined',
  '-Wcannot-profile',
  '-Wcast-align',
  '-Wcast-align=strict',
  # We do "bad" function casts all the time for event callbacks
  '-Wno-cast-function-type',
  '-Wchar-subscripts',
  '-Wclobbered',
  '-Wcomment',
  '-Wcomments',
  '-Wcoverage-mismatch',
  '-Wcpp',
  '-Wdangling-else',
  '-Wdate-time',
  '-Wdeclaration-after-statement',
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
  # -Wformat=2 implies -Wformat-nonliteral so we need to manually exclude it
  '-Wno-format-nonliteral',
  '-Wformat-overflow=2',
  '-Wformat-security',
  # -Wformat enables this by default, and we should keep it,
  # but need to rewrite various areas of code first
  '-Wno-format-truncation',
  '-Wformat-y2k',
  '-Wformat-zero-length',
  '-Wframe-address',
  '-Wframe-larger-than=@0@'.format(stack_frame_size),
  '-Wfree-nonheap-object',
  '-Whsa',
  '-Wif-not-aligned',
  '-Wignored-attributes',
  '-Wignored-qualifiers',
  '-Wimplicit',
  '-Wimplicit-fallthrough=5',
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
  '-Wjump-misses-init',
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
  '-Wnormalized=nfc',
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
  '-Wshift-overflow=2',
  # So we have -W enabled, and then have to explicitly turn off...
  '-Wno-sign-compare',
  '-Wsizeof-array-argument',
  '-Wsizeof-pointer-div',
  '-Wsizeof-pointer-memaccess',
  '-Wstrict-aliasing',
  '-Wstrict-prototypes',
  '-Wstringop-overflow=2',
  '-Wstringop-truncation',
  '-Wsuggest-attribute=cold',
  '-Wno-suggest-attribute=const',
  '-Wsuggest-attribute=format',
  '-Wsuggest-attribute=noreturn',
  '-Wno-suggest-attribute=pure',
  '-Wsuggest-final-methods',
  '-Wsuggest-final-types',
  '-Wswitch',
  '-Wswitch-bool',
  '-Wswitch-enum',
  '-Wswitch-unreachable',
  '-Wsync-nand',
  '-Wtautological-compare',
  '-Wtrampolines',
  '-Wtrigraphs',
  '-Wtype-limits',
  # Clang incorrectly complains about dup typedefs win gnu99 mode
  # so use this Clang-specific arg to keep it quiet
  '-Wno-typedef-redefinition',
  '-Wuninitialized',
  '-Wunknown-pragmas',
  '-Wunused',
  '-Wunused-but-set-parameter',
  '-Wunused-but-set-variable',
  '-Wunused-const-variable=2',
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

if cc.get_id() == 'clang'
    # Stop CLang from doing inter-procedural analysis of calls
    # between functions in the same compilation unit. Such an
    # optimization has been know to break the test suite by
    # making assumptions that a return value is a constant.
    # This makes it impossible to mock certain functions with
    # replacement definitions via LD_PRELOAD that have different
    # semantics.
    #
    # This is a bit of a big hammer, but alternatives don't work:
    #
    #  - 'weak' attribute - weak symbols get dropped from
    #    when the .a libs are combined into the .so
    #    see commit 407a281a8e2b6c5078ba1148535663ea64fd9314
    #
    #  - 'noipa' attribute - only available with GCC currently
    #    https://reviews.llvm.org/D101011
    cc_flags += [ '-fsemantic-interposition' ]
endif

supported_cc_flags = []
if get_option('warning_level') == '2'
  supported_cc_flags = cc.get_supported_arguments(cc_flags)

  # on aarch64 error: -fstack-protector not supported for this target
  if host_machine.cpu_family() != 'aarch64'
    if host_machine.system() in [ 'linux', 'freebsd', 'windows' ]
      # we prefer -fstack-protector-strong but fallback to -fstack-protector-all
      fstack_cflags = cc.first_supported_argument([
        '-fstack-protector-strong',
        '-fstack-protector-all',
      ])
      supported_cc_flags += fstack_cflags

      # When building with mingw using -fstack-protector requires libssp library
      # which is included by using -fstack-protector with linker.
      if fstack_cflags.length() == 1 and host_machine.system() == 'windows'
        add_project_link_arguments(fstack_cflags, language: 'c')
      endif
    endif
  endif

  if supported_cc_flags.contains('-Wlogical-op')
    # Broken in 6.0 and later
    #     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=69602
    w_logical_op_args = [ '-O2', '-Wlogical-op', '-Werror' ]
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
  w_double_promotion_args = [ '-O2', '-Wdouble-promotion', '-Werror' ]
  w_double_promotion_code = '''
    #include <math.h>

    int main(void) {
      float f = 0.0;
      return isnan(f);
    }
  '''
  if cc.compiles(w_double_promotion_code, args: w_double_promotion_args, name: '-Wdouble-promotion')
    supported_cc_flags += [ '-Wdouble-promotion' ]
  endif

  # Clang complains about unused static inline functions which are common
  # with G_DEFINE_AUTOPTR_CLEANUP_FUNC.
  w_unused_function_args = [ '-Wunused-function', '-Werror' ]
  w_unused_function_code = '''
    static inline void foo(void) {}

    int main(void) { return 0; }
  '''
  # -Wunused-function is implied by -Wall, we must turn it off explicitly.
  if not cc.compiles(w_unused_function_code, args: w_unused_function_args)
    supported_cc_flags += [ '-Wno-unused-function' ]
  endif

endif
add_project_arguments(supported_cc_flags, language: 'c')

if cc.has_argument('-Wsuggest-attribute=format')
  conf.set('WITH_SUGGEST_ATTRIBUTE_FORMAT', 1)
endif

# used in tests
cc_flags_relaxed_frame_limit = []
if cc.has_argument('-Wframe-larger-than=262144')
  cc_flags_relaxed_frame_limit += [
  '-Wframe-larger-than=262144',
  ]
endif

# various linker checks

libvirt_relro = cc.get_supported_link_arguments([
  '-Wl,-z,relro',
  '-Wl,-z,now',
])

libvirt_nodelete = cc.get_supported_link_arguments([
  '-Wl,-z,nodelete',
])

libvirt_no_undefined = []
if get_option('b_sanitize') == 'none'
  libvirt_no_undefined += cc.get_supported_link_arguments([
    '-Wl,-z,defs',
  ])
endif

libvirt_no_indirect = cc.get_supported_link_arguments([
  '-Wl,--no-copy-dt-needed-entries',
])

if host_machine.system() == 'windows'
  version_script_flags = '-Wl,'
elif host_machine.system() == 'darwin'
  # macOS libraries don't support symbol versioning
  version_script_flags = ''
else
  version_script_flags = '-Wl,--version-script='
endif

libvirt_flat_namespace = []
if host_machine.system() == 'darwin'
  libvirt_flat_namespace = '-Wl,-flat_namespace'
endif

libvirt_export_dynamic = cc.first_supported_link_argument([
  '-Wl,-export-dynamic',
  '-Wl,-export_dynamic',
])


# check availability of various common functions (non-fatal if missing)

functions = [
  'elf_aux_info',
  'explicit_bzero',
  'fallocate',
  'getauxval',
  'getegid',
  'geteuid',
  'getgid',
  'getifaddrs',
  'getmntent_r',
  'getpwuid_r',
  'getrlimit',
  'getuid',
  'getutxid',
  'if_indextoname',
  'mmap',
  'newlocale',
  'pipe2',
  'posix_fallocate',
  'posix_memalign',
  'prlimit',
  'sched_setscheduler',
  'setgroups',
  'setrlimit',
  'symlink',
  'sysctlbyname',
]

stat_functions = [
  '__lxstat',
  '__lxstat64',
  '__xstat',
  '__xstat64',
  'lstat',
  'lstat64',
  'stat',
  'stat64',
]

functions += stat_functions

foreach function : functions
  if cc.has_function(function)
    conf.set('WITH_@0@'.format(function.to_upper()), 1)
  endif
endforeach


foreach function : stat_functions
  if cc.has_header_symbol('sys/stat.h', function)
    conf.set('WITH_@0@_DECL'.format(function.to_upper()), 1)
  endif
endforeach


# various header checks

headers = [
  'asm/hwcap.h',
  'ifaddrs.h',
  'libtasn1.h',
  'linux/kvm.h',
  'mntent.h',
  'net/ethernet.h',
  'net/if.h',
  'pty.h',
  'pwd.h',
  'sched.h',
  'sys/auxv.h',
  'sys/ioctl.h',
  'sys/mount.h',
  'sys/syscall.h',
  'sys/ucred.h',
  'syslog.h',
  'util.h',
  'xlocale.h',
]

if host_machine.system() == 'freebsd'
  headers += 'libutil.h'
endif

foreach name : headers
  if cc.check_header(name)
    conf.set('WITH_@0@'.format(name.underscorify().to_upper()), 1)
  endif
endforeach

# check for kernel header required by src/util/virnetdevbridge.c
if host_machine.system() == 'linux'
  if not cc.check_header('linux/sockios.h')
    error('You must install kernel-headers in order to compile libvirt with QEMU or LXC support')
  endif
endif


# check various symbols

symbols = [
  # Check whether endian provides handy macros.
  [ 'endian.h', 'htole64' ],

  [ 'unistd.h', 'SEEK_HOLE' ],

  # Check for BSD approach for setting MAC addr
  [ 'net/if_dl.h', 'link_addr', '#include <sys/types.h>\n#include <sys/socket.h>' ],

  [ 'sched.h', 'cpu_set_t' ],
]

if host_machine.system() == 'linux'
  symbols += [
    # process management
    [ 'sys/syscall.h', 'SYS_pidfd_open' ],
  ]
endif

foreach symbol : symbols
  if cc.has_header_symbol(symbol[0], symbol[1], args: '-D_GNU_SOURCE', prefix: symbol.get(2, ''))
    conf.set('WITH_DECL_@0@'.format(symbol[1].to_upper()), 1)
  endif
endforeach

# Check for BSD approach for bridge management
brd_required_headers = '''#include <stdint.h>
#include <net/if.h>
#include <net/ethernet.h>'''
if (cc.has_header_symbol('net/if_bridgevar.h', 'BRDGSFD', prefix: brd_required_headers) and
    cc.has_header_symbol('net/if_bridgevar.h', 'BRDGADD', prefix: brd_required_headers) and
    cc.has_header_symbol('net/if_bridgevar.h', 'BRDGDEL', prefix: brd_required_headers))
  conf.set('WITH_BSD_BRIDGE_MGMT', 1)
endif

# Check for BSD CPU affinity availability
if cc.has_header_symbol('sys/cpuset.h', 'cpuset_getaffinity', prefix: '#include <sys/param.h>')
  conf.set('WITH_BSD_CPU_AFFINITY', 1)
endif

# whether Mach clock routines are available
if (cc.has_header_symbol('mach/clock.h', 'clock_serv_t') and
    cc.has_header_symbol('mach/clock.h', 'host_get_clock_service') and
    cc.has_header_symbol('mach/clock.h', 'clock_get_time'))
  conf.set('WITH_MACH_CLOCK_ROUTINES', 1)
endif


# check various types

types = [
  [ 'struct ifreq', '#include <sys/socket.h>\n#include <net/if.h>'] ,
  [ 'struct sockpeercred', '#include <sys/socket.h' ],
]

foreach type : types
  if cc.has_type(type[0], prefix: type[1])
    name = type[0].underscorify().to_upper()
    conf.set('WITH_@0@'.format(name), 1)
  endif
endforeach

if host_machine.system() == 'windows'
  uid_types = [
    'uid_t',
    'gid_t',
  ]
  foreach type : uid_types
    if not cc.has_type(type, prefix: '#include <sys/types.h>')
      conf.set(type, 'int')
    endif
  endforeach
endif


# check various members

members = [
  # Check for Linux vs. BSD ifreq members
  [ 'struct ifreq', 'ifr_newname', '#include <sys/socket.h>\n#include <net/if.h>' ],
  [ 'struct ifreq', 'ifr_ifindex', '#include <sys/socket.h>\n#include <net/if.h>' ],
  [ 'struct ifreq', 'ifr_index', '#include <sys/socket.h>\n#include <net/if.h>' ],
  [ 'struct ifreq', 'ifr_hwaddr', '#include <sys/socket.h>\n#include <net/if.h>' ],
]

foreach member : members
  if cc.has_member(member[0], member[1], prefix: member[2])
    type = member[0].underscorify().to_upper()
    member = member[1].underscorify().to_upper()
    conf.set('WITH_@0@_@1@'.format(type, member), 1)
  endif
endforeach


# check various types sizeof

conf.set('SIZEOF_LONG', cc.sizeof('long'))


# Where we look for daemons and admin binaries during configure

libvirt_sbin_path = []

if host_machine.system() != 'windows'
  libvirt_sbin_path += [
    '/sbin',
    '/usr/sbin',
    '/usr/local/sbin',
  ]
endif


# required programs check

required_programs = [
  'perl',
  'python3',
  'xmllint',
  'xsltproc',
]

required_programs_groups = [
  { 'name': 'rpcgen', 'prog': [ 'rpcgen', 'portable-rpcgen' ] },
]

if host_machine.system() == 'freebsd'
  required_programs += 'ifconfig'
endif

foreach name : required_programs
  prog = find_program(name, dirs: libvirt_sbin_path)
  varname = name.underscorify()
  conf.set_quoted(varname.to_upper(), prog.full_path())
  set_variable('@0@_prog'.format(varname), prog)
endforeach

foreach item : required_programs_groups
  prog = find_program(item.get('prog'), dirs: libvirt_sbin_path)
  varname = item.get('name').underscorify()
  conf.set_quoted(varname.to_upper(), prog.full_path())
  set_variable('@0@_prog'.format(varname), prog)
endforeach

# optional programs

optional_programs = [
  'augparse',
  'dmidecode',
  'ebtables',
  'flake8',
  'ip',
  'ip6tables',
  'iptables',
  'iscsiadm',
  'mdevctl',
  'mm-ctl',
  'modprobe',
  'ovs-vsctl',
  'passt',
  'pdwtags',
  'rmmod',
  'scrub',
  'tc',
  'udevadm',
]

foreach name : optional_programs
  prog = find_program(name, required: false, dirs: libvirt_sbin_path)
  varname = name.underscorify()
  if prog.found()
    prog_path = prog.full_path()
  else
    prog_path = name
  endif

  conf.set_quoted(varname.to_upper(), prog_path)
  set_variable('@0@_prog'.format(varname), prog)
endforeach


# early checks where lot of other packages depend on the result

if not get_option('driver_remote').disabled()
  # On MinGW portablexdr provides XDR functions, on linux they are
  # provided by libtirpc and on FreeBSD/macOS there is no need to
  # use extra library as it's provided by libc directly.
  if host_machine.system() == 'windows'
    xdr_dep = cc.find_library('portablexdr', required: get_option('driver_remote'))
  elif host_machine.system() in [ 'linux', 'gnu' ]
    xdr_dep = dependency('libtirpc', required: get_option('driver_remote'))
  elif host_machine.system() in [ 'freebsd', 'darwin' ]
    xdr_dep = cc.find_library('c', required: get_option('driver_remote'))
  else
    xdr_dep = dependency('', required: false)
  endif

  if xdr_dep.found()
    conf.set('WITH_REMOTE', 1)
  elif get_option('driver_remote').enabled()
    error('XDR is required for remote driver')
  endif
else
  xdr_dep = dependency('', required: false)
endif


# generic build dependencies

acl_dep = dependency('libacl', required: false)
if acl_dep.found()
  conf.set('WITH_LIBACL', 1)
endif

apparmor_dep = dependency('libapparmor', required: get_option('apparmor'))
if apparmor_dep.found()
  conf.set('WITH_APPARMOR', 1)
  if apparmor_dep.version().version_compare('>=3.0.0')
    conf.set('WITH_APPARMOR_3', 1)
  endif
  conf.set_quoted('APPARMOR_DIR', sysconfdir / 'apparmor.d')
  conf.set_quoted('APPARMOR_PROFILES_PATH', '/sys/kernel/security/apparmor/profiles')
endif

if not get_option('apparmor_profiles').disabled()
  apparmor_profiles_enable = true

  if not conf.has('WITH_APPARMOR')
    apparmor_profiles_enable = false
    if get_option('apparmor_profiles').enabled()
      error('Cannot enable apparmor_profiles without apparmor')
    endif
  endif

  if apparmor_profiles_enable
    conf.set('WITH_APPARMOR_PROFILES', 1)
  endif
endif

# FIXME rewrite to use dependency() once we can use 2.4.48
attr_dep = cc.find_library('attr', required: get_option('attr'))
if attr_dep.found()
  conf.set('WITH_LIBATTR', 1)
endif

audit_dep = dependency('audit', required: get_option('audit'))
if audit_dep.found()
  conf.set('WITH_AUDIT', 1)
endif

bash_completion_version = '2.0'
bash_completion_dep = dependency('bash-completion', version: '>=' + bash_completion_version, required: get_option('bash_completion'))

blkid_version = '2.17'
blkid_dep = dependency('blkid', version: '>=' + blkid_version, required: get_option('blkid'))
if blkid_dep.found()
  conf.set('WITH_BLKID', 1)
endif

capng_dep = dependency('libcap-ng', required: get_option('capng'))
if capng_dep.found()
  conf.set('WITH_CAPNG', 1)
endif

curl_version = '7.19.1'
curl_dep = dependency('libcurl', version: '>=' + curl_version, required: get_option('curl'))
if curl_dep.found()
  conf.set('WITH_CURL', 1)
endif

devmapper_version = '1.0.0'
devmapper_dep = dependency('devmapper', version: '>=' + devmapper_version, required: false)
if devmapper_dep.found()
  conf.set('WITH_DEVMAPPER', 1)
endif

dlopen_use = host_machine.system() != 'windows'
dlopen_dep = cc.find_library('dl', required: dlopen_use)
if dlopen_dep.found()
  if not cc.check_header('dlfcn.h')
    error('Unable to find dlfcn.h')
  endif
  conf.set('WITH_DLFCN_H', 1)
endif

fuse_version = '3.1.0'
fuse_dep = dependency('fuse3', version: '>=' + fuse_version, required: false)
if fuse_dep.found()
  conf.set('WITH_FUSE', 3)
else
  fuse_version = '2.8.6'
  fuse_dep = dependency('fuse', version: '>=' + fuse_version, required: get_option('fuse'))
  if fuse_dep.found()
    conf.set('WITH_FUSE', 1)
  endif
endif

glib_version = '2.56.0'
glib_dep = dependency('glib-2.0', version: '>=' + glib_version)
gobject_dep = dependency('gobject-2.0', version: '>=' + glib_version)
if host_machine.system() == 'windows'
  gio_dep = dependency('gio-2.0', version: '>=' + glib_version)
else
  gio_dep = dependency('gio-unix-2.0', version: '>=' + glib_version)
endif
glib_dep = declare_dependency(
  dependencies: [ glib_dep, gobject_dep, gio_dep ],
)
glib_version_arr = glib_version.split('.')
glib_version_str = 'GLIB_VERSION_@0@_@1@'.format(glib_version_arr[0], glib_version_arr[1])
# Ask for warnings for anything that was marked deprecated in
# the defined version, or before. It is a candidate for rewrite.
conf.set('GLIB_VERSION_MIN_REQUIRED', glib_version_str)
# Ask for warnings if code tries to use function that did not
# exist in the defined version. These risk breaking builds
conf.set('GLIB_VERSION_MAX_ALLOWED', glib_version_str)

glusterfs_version = '3.4.1'
glusterfs_dep = dependency('glusterfs-api', version: '>=' + glusterfs_version, required: get_option('glusterfs'))

gnutls_version = '3.6.0'
gnutls_dep = dependency('gnutls', version: '>=' + gnutls_version)

# Check for BSD kvm (kernel memory interface)
if host_machine.system() == 'freebsd'
  libkvm_dep = cc.find_library('kvm')
else
  libkvm_dep = dependency('', required: false)
endif

libiscsi_version = '1.18.0'
libiscsi_dep = dependency('libiscsi', version: '>=' + libiscsi_version, required: get_option('libiscsi'))

if not get_option('nbdkit').disabled()
  libnbd_version = '1.0'
  libnbd_dep = dependency('libnbd', version: '>=' + libnbd_version, required: false)

  nbdkit_requested = get_option('nbdkit').enabled()
  nbdkit_syscall_ok = conf.has('WITH_DECL_SYS_PIDFD_OPEN')
  nbdkit_libnbd_ok = libnbd_dep.found()

  if not nbdkit_syscall_ok and nbdkit_requested
    error('nbdkit support requires pidfd_open(2)')
  endif
  if not nbdkit_libnbd_ok and nbdkit_requested
    error('nbdkit support requires libnbd')
  endif

  if nbdkit_syscall_ok and nbdkit_libnbd_ok
    conf.set('WITH_NBDKIT', 1)
  endif
endif
if not conf.has('WITH_NBDKIT')
  libnbd_dep = dependency('', required: false)
endif

libnl_version = '3.0'
if not get_option('libnl').disabled() and host_machine.system() == 'linux'
  libnl_dep = dependency('libnl-3.0', version: '>=' + libnl_version, required: get_option('libnl'))
  libnl_route_dep = dependency('libnl-route-3.0', version: '>=' + libnl_version, required: get_option('libnl'))

  if libnl_dep.found() and libnl_route_dep.found()
    libnl_dep = declare_dependency(
      dependencies: [ libnl_dep, libnl_route_dep ],
    )
    conf.set('WITH_LIBNL', 1)
  endif
elif get_option('libnl').enabled()
  error('libnl can be enabled only on linux')
else
  libnl_dep = dependency('', required: false)
endif

libparted_version = '1.8.0'
libparted_dep = dependency('libparted', version: '>=' + libparted_version, required: get_option('storage_disk'))

libpcap_version = '1.5.0'
if not get_option('libpcap').disabled()
  libpcap_dep = dependency('pcap', version: '>=' + libpcap_version, required: get_option('libpcap'))
  if libpcap_dep.found()
    conf.set('WITH_LIBPCAP', 1)
  endif
else
  libpcap_dep = dependency('', required: false)
endif

libssh_version = '0.8.1'
if conf.has('WITH_REMOTE')
  libssh_dep = dependency('libssh', version: '>=' + libssh_version, required: get_option('libssh'))
  if libssh_dep.found()
    conf.set('WITH_LIBSSH', 1)
  endif
else
  libssh_dep = dependency('', required: false)
endif

libssh2_version = '1.3'
if conf.has('WITH_REMOTE')
  libssh2_dep = dependency('libssh2', version: '>=' + libssh2_version, required: get_option('libssh2'))
  if libssh2_dep.found()
    conf.set('WITH_SSH2', 1)
  endif
else
  libssh2_dep = dependency('', required: false)
endif

libxml_version = '2.9.1'
libxml_dep = dependency('libxml-2.0', version: '>=' + libxml_version)

libm_dep = cc.find_library('m')

netcf_version = '0.1.8'
if not get_option('netcf').disabled()
  netcf_dep = dependency('netcf', version: '>=' + netcf_version, required: get_option('netcf'))
  if netcf_dep.found()
    conf.set('WITH_NETCF', 1)
  endif
else
  netcf_dep = dependency('', required: false)
endif

have_gnu_gettext_tools = false
if not get_option('nls').disabled()
  have_gettext = cc.has_function('gettext')
  if not have_gettext
    intl_dep = cc.find_library('intl', required: false)
    have_gettext = intl_dep.found()
  else
    intl_dep = dependency('', required: false)
  endif
  if not have_gettext and get_option('nls').enabled()
    error('gettext() is required to build libvirt')
  endif

  if cc.check_header('libintl.h')
    conf.set('WITH_LIBINTL_H', 1)
  elif get_option('nls').enabled()
    error('libintl.h is required to build libvirt')
  endif

  gettext_progs = [
    'xgettext',
    'msgfmt',
    'msgmerge',
  ]
  foreach name : gettext_progs
    prog = find_program(name, required: false)
    set_variable('@0@_prog'.format(name), prog)
  endforeach

  if xgettext_prog.found() and msgfmt_prog.found() and msgmerge_prog.found()
    rc = run_command(msgfmt_prog, '--version', check: false)
    if rc.returncode() == 0 and rc.stdout().contains('GNU gettext')
      have_gnu_gettext_tools = true
    endif
  endif
else
  intl_dep = dependency('', required: false)
endif

numactl_dep = dependency('numa', required: get_option('numactl'))
if numactl_dep.found()
  conf.set('WITH_NUMACTL', 1)
  if cc.has_function('numa_set_preferred_many', dependencies: numactl_dep)
    conf.set('WITH_NUMACTL_SET_PREFERRED_MANY', 1)
  endif
endif

openwsman_version = '2.6.3'
openwsman_dep = dependency('openwsman', version: '>=' + openwsman_version, required: get_option('openwsman'))

parallels_sdk_version = '7.0.22'
parallels_sdk_dep = dependency('parallels-sdk', version: '>=' + parallels_sdk_version, required: false)

pciaccess_version = '0.10.0'
pciaccess_dep = dependency('pciaccess', version: '>=' + pciaccess_version, required: get_option('pciaccess'))

rbd_dep = cc.find_library('rbd', required: get_option('storage_rbd'))
rados_dep = cc.find_library('rados', required: get_option('storage_rbd'))
if rbd_dep.found() and not cc.has_function('rbd_get_features', dependencies: rbd_dep)
  rbd_dep = dependency('', required: false)
endif
if rbd_dep.found() and rados_dep.found()
  if cc.has_function('rbd_list2', dependencies: rbd_dep)
    conf.set('WITH_RBD_LIST2', 1)
  endif

  rbd_dep = declare_dependency(dependencies: [ rbd_dep, rados_dep ])
else
  rbd_dep = dependency('', required: false)
endif

# readline 7.0 is the first version which includes pkg-config support
readline_version = '7.0'
if not get_option('readline').disabled()
  readline_dep = dependency('readline', version: '>=' + readline_version, required: false)
  if not readline_dep.found()
    readline_dep = cc.find_library('readline', required: get_option('readline'))

    if readline_dep.found()
      # This variable is present in all reasonable (5.0+) readline versions;
      # however, the macOS base system contains a library called libedit which
      # takes over the readline name despite lacking many of its features. We
      # want to make sure we only enable readline support when linking against
      # the actual readline library, and the availability of this specific
      # variable is as good a witness for that fact as any.
      correct_rl = cc.has_header_symbol('readline/readline.h', 'rl_completion_quote_character', prefix: '#include <stdio.h>')
      if not correct_rl
        if get_option('readline').enabled()
          error('readline is missing rl_completion_quote_character')
        else
          readline_dep = dependency('', required: false)
        endif
      endif
    endif
  endif
  if readline_dep.found()
    # We need this to avoid compilation issues with modern compilers.
    # See 9ea3424a178 for a more detailed explanation
    readline_dep = declare_dependency(
      compile_args: [ '-D_FUNCTION_DEF' ],
      dependencies: [ readline_dep ],
    )

    conf.set('WITH_READLINE', 1)
  endif
else
  readline_dep = dependency('', required: false)
endif

if not get_option('sanlock').disabled()
  sanlock_dep = dependency('libsanlock_client', required: get_option('sanlock'))

  if sanlock_dep.found()
    conf.set('WITH_SANLOCK', 1)
    # check for sanlock_strerror introduced in sanlock-3.5.0
    if cc.has_function('sanlock_strerror', dependencies: sanlock_dep)
      conf.set('WITH_SANLOCK_STRERROR', 1)
    endif
  endif
else
  sanlock_dep = dependency('', required: false)
endif

sasl_version = '2.1.26'
if conf.has('WITH_REMOTE')
  sasl_dep = dependency('libsasl2', version: '>=' + sasl_version, required: get_option('sasl'))
  if sasl_dep.found()
    conf.set('WITH_SASL', 1)
  endif
else
  sasl_dep = dependency('', required: false)
endif

selinux_dep = dependency('libselinux', required: get_option('selinux'))
if selinux_dep.found()
  selinux_mount = get_option('selinux_mount')
  if selinux_mount == ''
    if run_command('test', '-d', '/sys/fs/selinux', check: false).returncode() == 0
      selinux_mount = '/sys/fs/selinux'
    else
      selinux_mount = '/selinux'
    endif
  endif
  conf.set_quoted('SELINUX_MOUNT', selinux_mount)
  conf.set('WITH_SELINUX', 1)
endif

thread_dep = dependency('threads')
pthread_sigmask_code = '''
  #include <sys/types.h>
  #include <signal.h>

  int main() {
      #ifdef pthread_sigmask
      int (*foo)(int, const sigset_t *, sigset_t *) = &pthread_sigmask;
      return !foo;
      #endif

      return 0;
  }
'''
if not cc.compiles(pthread_sigmask_code)
  conf.set('FUNC_PTHREAD_SIGMASK_BROKEN', 1)
endif

udev_version = '219'
udev_dep = dependency('libudev', version: '>=' + udev_version, required: get_option('udev'))
if udev_dep.found()
  conf.set('WITH_UDEV', 1)
endif

libutil_dep = cc.find_library('util', required: false)

if host_machine.system() == 'windows'
  ole32_dep = cc.find_library('ole32')
  oleaut32_dep = cc.find_library('oleaut32')
  winsock2_dep = cc.find_library('ws2_32')
  win32_dep = declare_dependency(
    dependencies: [
      ole32_dep,
      oleaut32_dep,
      winsock2_dep,
    ],
  )
  if get_option('default_library') == 'static'
    win32_flags = [ '-DLIBVIRT_STATIC' ]
  else
    win32_flags = []
  endif
  win32_link_flags = [ '-Wl,-no-undefined' ]
else
  win32_dep = dependency('', required: false)
  win32_flags = []
  win32_link_flags = []
endif

wireshark_version = '2.6.0'
wireshark_dep = dependency('wireshark', version: '>=' + wireshark_version, required: get_option('wireshark_dissector'))
if wireshark_dep.found()
  if not xdr_dep.found()
    if get_option('wireshark_dissector').enabled()
      error('XDR is required for wireshark plugin')
    else
      wireshark_dep = dependency('', required: false)
    endif
  endif
endif

if wireshark_dep.found()
  wireshark_plugindir = get_option('wireshark_plugindir')
  if wireshark_plugindir == ''
    wireshark_plugindir = wireshark_dep.get_variable(pkgconfig : 'plugindir')
  endif

  wireshark_prefix = wireshark_dep.get_variable(pkgconfig : 'prefix')
  if wireshark_prefix == ''
    # If wireshark's prefix cannot be retrieved from pkg-config,
    # this is our best bet.
    wireshark_prefix = '/usr'
  endif
  # Replace wireshark's prefix with our own.
  # There is no replace method in meson so we have to workaround it.
  rc = run_command(
    'python3', '-c',
    'print("@0@".replace("@1@", "@2@"))'.format(
      wireshark_plugindir, wireshark_prefix, prefix,
    ),
    check: true,
  )
  wireshark_plugindir = rc.stdout().strip()

  # Since wireshark 2.5.0 plugins can't live in top level plugindir but have
  # to be under one of ["epan", "wiretap", "codecs"] subdir. The first one looks okay.
  wireshark_plugindir = wireshark_plugindir / 'epan'

  # Wireshark is installing ws_version.h since v2.9.0, but some distributions
  # are not shipping it.
  if cc.check_header('wireshark/ws_version.h')
    conf.set('WITH_WS_VERSION', 1)
  endif
endif

yajl_version = '2.0.3'
yajl_dep = dependency('yajl', version: '>=' + yajl_version, required: get_option('yajl'))
if yajl_dep.found()
  # Kludge for yajl include path on non-Linux
  #
  # As of 2.1.0, upstream yajl.pc has -I${includedir}/yajl among
  # its Cflags, which is clearly wrong. This does not affect Linux
  # because ${includedir} is already part of the default include path,
  # but on other platforms that's not the case and the result is that
  # <yajl/yajl.h> can't be located, causing the build to fail.
  #
  # Since upstream development for yajl has stopped years ago, there's
  # little hope of this issue getting fixed by a new upstream release.
  # Some non-Linux operating systems such as FreeBSD have elected to
  # carry a small downstream patch, but in the case of Homebrew on
  # macOS this approach has been rejected[1] and so we're left with no
  # choice but to work around the issue ourselves.
  #
  # [1] https://github.com/Homebrew/homebrew-core/pull/74516
  if host_machine.system() != 'linux'
    yajl_includedir = yajl_dep.get_variable(pkgconfig : 'includedir')
    if yajl_includedir.contains('include/yajl')
      rc = run_command(
        'python3', '-c',
        'print("@0@".replace("@1@", "@2@"))'.format(
          yajl_includedir, 'include/yajl', 'include',
        ),
        check: true,
      )
      yajl_includedir = rc.stdout().strip()
      yajl_dep = declare_dependency(
        compile_args: [ '-I' + yajl_includedir ],
        dependencies: [ yajl_dep ],
      )
    endif
  endif

  conf.set('WITH_YAJL', 1)
endif


# generic build dependencies checks

if bash_completion_dep.found() and not readline_dep.found()
  if get_option('bash_completion').enabled()
    error('readline is required for bash completion support')
  else
    bash_completion_dep = dependency('', required: false)
  endif
endif
if bash_completion_dep.found()
  bash_completion_dir = get_option('bash_completion_dir')
  if bash_completion_dir == ''
    bash_completion_dir = bash_completion_dep.get_variable(pkgconfig : 'completionsdir')
    bash_completion_prefix = bash_completion_dep.get_variable(pkgconfig : 'prefix')
    rc = run_command(
      'python3', '-c',
      'print("@0@".replace("@1@", "@2@"))'.format(
        bash_completion_dir, bash_completion_prefix, prefix,
      ),
      check: true,
    )
    bash_completion_dir = rc.stdout().strip()
  endif
endif

if not get_option('firewalld').disabled()
  firewalld_enable = true

  if host_machine.system() != 'linux'
    firewalld_enable = false
    if get_option('firewalld').enabled()
      error('firewalld support can only be enabled on Linux')
    endif
  endif

  if firewalld_enable
    conf.set('WITH_FIREWALLD', 1)
  endif
endif

if not get_option('firewalld_zone').disabled() and conf.has('WITH_FIREWALLD')
  conf.set('WITH_FIREWALLD_ZONE', 1)
elif get_option('firewalld_zone').enabled()
  error('You must have firewalld support enabled to enable firewalld_zone')
endif

if not get_option('polkit').disabled()
  polkit_enable = true

  if get_option('polkit').auto()
    pkcheck_prog = find_program('pkcheck', required: false, dirs: libvirt_sbin_path)
    polkit_enable = pkcheck_prog.found()
  endif

  if host_machine.system() == 'windows'
    polkit_enable = false
    if get_option('polkit').enabled()
      error('polkit support cannot be enabled on Windows')
    endif
  endif

  if polkit_enable
    conf.set('WITH_POLKIT', 1)
  endif
endif

if udev_dep.found() and not pciaccess_dep.found()
  error('You must install the pciaccess module to build with udev')
endif


# build driver options

remote_default_mode = get_option('remote_default_mode')
if remote_default_mode == 'direct'
  conf.set('REMOTE_DRIVER_AUTOSTART_DIRECT', '1')
endif

if not get_option('driver_libvirtd').disabled()
  use_libvirtd = true

  if host_machine.system() == 'windows'
    use_libvirtd = false
    if get_option('driver_libvirtd').enabled()
      error('libvirtd daemon is not supported on windows')
    endif
  endif

  if not conf.has('WITH_REMOTE')
    use_libvirtd = false
    if get_option('driver_libvirtd').enabled()
      error('remote driver is required for libvirtd daemon')
    endif
  endif

  if use_libvirtd
    conf.set('WITH_LIBVIRTD', 1)
  endif
endif

if not get_option('driver_bhyve').disabled() and host_machine.system() == 'freebsd'
  bhyve_prog = find_program('bhyve', required: get_option('driver_bhyve'))
  bhyvectl_prog = find_program('bhyvectl', required: get_option('driver_bhyve'))
  bhyveload_prog = find_program('bhyveload', required: get_option('driver_bhyve'))

  if bhyve_prog.found() and bhyvectl_prog.found() and bhyveload_prog.found()
    conf.set('WITH_BHYVE', 1)
    conf.set_quoted('BHYVE', bhyve_prog.full_path())
    conf.set_quoted('BHYVECTL', bhyvectl_prog.full_path())
    conf.set_quoted('BHYVELOAD', bhyveload_prog.full_path())
  endif
elif get_option('driver_bhyve').enabled()
  error('The bhyve driver cannot be enabled')
endif

if not get_option('driver_esx').disabled() and curl_dep.found()
  conf.set('WITH_ESX', 1)
  conf.set('WITH_VMX', 1)
elif get_option('driver_esx').enabled()
  error('Curl is required for the ESX driver')
endif

if not get_option('driver_hyperv').disabled() and openwsman_dep.found()
  conf.set('WITH_HYPERV', 1)
elif get_option('driver_hyperv').enabled()
  error('openwsman is required for the Hyper-V driver')
endif

if not get_option('driver_interface').disabled() and conf.has('WITH_LIBVIRTD') and (udev_dep.found() or conf.has('WITH_NETCF'))
  conf.set('WITH_INTERFACE', 1)
elif get_option('driver_interface').enabled()
  error('Requested the Interface driver without netcf or udev and libvirtd support')
endif

if not get_option('driver_libxl').disabled() and conf.has('WITH_LIBVIRTD')
  libxl_version = '4.9.0'
  libxl_dep = dependency('xenlight', version: '>=' + libxl_version, required: get_option('driver_libxl'))

  if libxl_dep.found()
    libxl_firmware_dir = libxl_dep.get_variable(pkgconfig : 'xenfirmwaredir', default_value: '')
    libxl_execbin = libxl_dep.get_variable(pkgconfig : 'libexec_bin', default_value: '')
    if libxl_firmware_dir != ''
      conf.set_quoted('LIBXL_FIRMWARE_DIR', libxl_firmware_dir)
    endif
    if libxl_execbin != ''
      conf.set_quoted('LIBXL_EXECBIN_DIR', libxl_execbin)
    endif

    # If building with libxl, use the libxl utility header and lib too
    if cc.check_header('libxlutil.h')
      conf.set('WITH_LIBXLUTIL_H', 1)
    endif
    xl_util_dep = dependency('xlutil')

    xen_store_dep = dependency('xenstore')
    xtl_link_dep = dependency('xentoollog')

    # Upstream Xen failed to advertise LIBXL_API_VERSION 0x040700 and
    # 0x040800 until the Xen 4.13 release. For Xen versions 4.9-4.12
    # we'll need to stick with version 0x040500.
    if libxl_dep.version().version_compare('>=4.13.0')
      LIBXL_API_VERSION='0x041300'
    else
      LIBXL_API_VERSION='0x040500'
    endif
    libxl_dep = declare_dependency(
      compile_args: '-DLIBXL_API_VERSION=' + LIBXL_API_VERSION,
      dependencies: [
        libxl_dep,
        xtl_link_dep,
        xl_util_dep,
        xen_store_dep,
      ],
    )

    # Check if Xen has support for PVH
    if cc.has_header_symbol('libxl.h', 'LIBXL_DOMAIN_TYPE_PVH')
      conf.set('WITH_XEN_PVH', 1)
    endif

    conf.set('WITH_LIBXL', 1)
  endif
elif get_option('driver_libxl').enabled()
  error('libvirtd is required for libxenlight')
endif

if not get_option('driver_lxc').disabled() and host_machine.system() == 'linux' and conf.has('WITH_LIBVIRTD')
  conf.set('WITH_LXC', 1)
elif get_option('driver_lxc').enabled()
  error('linux and remote_driver are required for LXC')
endif

if not get_option('driver_ch').disabled() and host_machine.system() == 'linux' and (host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'aarch64')
  use_ch = true

  if not conf.has('WITH_LIBVIRTD')
    use_ch = false
    if get_option('driver_ch').enabled()
      error('libvirtd is required to build Cloud-Hypervisor driver')
    endif
  endif

  if not yajl_dep.found()
    use_ch = false
    if get_option('driver_ch').enabled()
      error('YAJL 2 is required to build Cloud-Hypervisor driver')
    endif
  endif

  if not curl_dep.found()
    use_ch = false
    if get_option('driver_ch').enabled()
      error('curl is required to build Cloud-Hypervisor driver')
    endif
  endif

  if use_ch
    conf.set('WITH_CH', 1)

    default_ch_user = 'root'
    default_ch_group = 'root'
    ch_user = get_option('ch_user')
    if ch_user == ''
      ch_user = default_ch_user
    endif
    ch_group = get_option('ch_group')
    if ch_group == ''
      ch_group = default_ch_group
    endif
    conf.set_quoted('CH_USER', ch_user)
    conf.set_quoted('CH_GROUP', ch_group)
  endif
endif

if not get_option('driver_network').disabled() and conf.has('WITH_LIBVIRTD')
  conf.set('WITH_NETWORK', 1)
elif get_option('driver_network').enabled()
  error('libvirtd must be enabled to build the network driver')
endif

if udev_dep.found() and conf.has('WITH_LIBVIRTD')
  conf.set('WITH_NODE_DEVICES', 1)
endif

if not get_option('driver_openvz').disabled() and host_machine.system() == 'linux'
  conf.set('WITH_OPENVZ', 1)
elif get_option('driver_openvz').enabled()
  error('OpenVZ driver can be enabled on Linux only')
endif

if not get_option('driver_qemu').disabled()
  use_qemu = true

  if not yajl_dep.found()
    use_qemu = false
    if get_option('driver_qemu').enabled()
      error('YAJL 2 is required to build QEMU driver')
    endif
  endif

  if not conf.has('WITH_LIBVIRTD')
    use_qemu = false
    if get_option('driver_qemu').enabled()
      error('libvirtd is required to build QEMU driver')
    endif
  endif

  if use_qemu
    conf.set('WITH_QEMU', 1)

    qemu_moddir = get_option('qemu_moddir')
    if qemu_moddir == ''
      qemu_moddir = libdir / 'qemu'
    endif
    conf.set_quoted('QEMU_MODDIR', qemu_moddir)

    qemu_datadir = get_option('qemu_datadir')
    if qemu_datadir == ''
      qemu_datadir = datadir / 'qemu'
    endif
    conf.set_quoted('QEMU_DATADIR', qemu_datadir)

    qemu_user = get_option('qemu_user')
    qemu_group = get_option('qemu_group')
    if (qemu_user == '' and qemu_group != '') or (qemu_user != '' and qemu_group == '')
      error('Please specify both qemu_user and qemu_group or neither of them')
    endif
    if qemu_user == '' and qemu_group == ''
      if host_machine.system() in [ 'freebsd', 'darwin' ]
        qemu_user = 'root'
        qemu_group = 'wheel'
      else
        # RHEL and CentOS both have ID_LIKE=fedora, SLES has ID_LIKE=suse
        if (os_release.contains('fedora') or
            os_release.contains('gentoo') or
            os_release.contains('suse'))
          qemu_user = 'qemu'
          qemu_group = 'qemu'
        # Ubuntu has ID_LIKE=debian so we need to handle it first
        elif os_release.contains('ubuntu')
          qemu_user = 'libvirt-qemu'
          qemu_group = 'kvm'
        elif (os_release.contains('arch') or
              os_release.contains('debian'))
          qemu_user = 'libvirt-qemu'
          qemu_group = 'libvirt-qemu'
        else
          qemu_user = 'root'
          qemu_group = 'root'
        endif
      endif
    endif
    conf.set_quoted('QEMU_USER', qemu_user)
    conf.set_quoted('QEMU_GROUP', qemu_group)

    qemu_slirp_prog = find_program(
      'slirp-helper',
      dirs: [ '/usr/bin', '/usr/libexec' ],
      required: false
    )
    if qemu_slirp_prog.found()
      qemu_slirp_path = qemu_slirp_prog.full_path()
    else
      qemu_slirp_path = '/usr/bin/slirp-helper'
    endif
    conf.set_quoted('QEMU_SLIRP_HELPER', qemu_slirp_path)
  endif
endif

if not get_option('driver_secrets').disabled() and conf.has('WITH_LIBVIRTD')
  conf.set('WITH_SECRETS', 1)
endif

if not get_option('driver_test').disabled()
  conf.set('WITH_TEST', 1)
endif

if not get_option('driver_vbox').disabled() and conf.has('WITH_LIBVIRTD')
  conf.set('WITH_VBOX', 1)
  conf.set_quoted('VBOX_XPCOMC_DIR', get_option('vbox_xpcomc_dir'))
endif

if not get_option('driver_vmware').disabled()
  conf.set('WITH_VMWARE', 1)
  conf.set('WITH_VMX', 1)
endif

if not get_option('driver_vz').disabled() and parallels_sdk_dep.found()
  conf.set('WITH_VZ', 1)
elif get_option('driver_vz').enabled()
  error('Parallels Virtualization SDK is needed to build the Virtuozzo driver.')
endif

if not get_option('secdriver_apparmor').disabled() and apparmor_dep.found()
  conf.set('WITH_SECDRIVER_APPARMOR', 1)
elif get_option('secdriver_apparmor').enabled()
  error('You must install the AppArmor development package in order to compile libvirt.')
endif

if not get_option('secdriver_selinux').disabled() and selinux_dep.found()
  conf.set('WITH_SECDRIVER_SELINUX', 1)
elif get_option('secdriver_selinux').enabled()
  error('You must install the libselinux development package in order to compile libvirt.')
endif

if conf.has('WITH_QEMU') or conf.has('WITH_LXC') or conf.has('WITH_NETWORK')
  conf.set('WITH_BRIDGE', 1)
endif


# check for storage drivers

use_storage = false

if conf.has('WITH_LIBVIRTD')
  if not get_option('storage_dir').disabled()
    use_storage = true
    conf.set('WITH_STORAGE_DIR', 1)
  endif

  if not get_option('storage_disk').disabled() and devmapper_dep.found() and libparted_dep.found()
    use_storage = true
    conf.set('WITH_STORAGE_DISK', 1)
  elif get_option('storage_disk').enabled()
    error('You must install libparted and libdevmapper to compile libvirt with disk storage driver')
  endif

  if not get_option('storage_fs').disabled()
    fs_enable = true

    # storage-fs does not work on macOS
    if host_machine.system() == 'darwin'
      fs_enable = false
    endif

    if fs_enable and not cc.check_header('mntent.h')
      if get_option('storage_fs').enabled()
        error('<mntent.h> is required for the FS storage driver')
      else
        fs_enable = false
      endif
    endif

    if fs_enable
      mount_prog = find_program('mount', required: get_option('storage_fs'), dirs: libvirt_sbin_path)
      umount_prog = find_program('umount', required: get_option('storage_fs'), dirs: libvirt_sbin_path)
      mkfs_prog = find_program('mkfs', required: get_option('storage_fs'), dirs: libvirt_sbin_path)

      if not mount_prog.found() or not umount_prog.found() or not mkfs_prog.found()
        fs_enable = false
      endif
    endif

    if fs_enable
      use_storage = true

      conf.set('WITH_STORAGE_FS', 1)
      conf.set_quoted('MOUNT', mount_prog.full_path())
      conf.set_quoted('UMOUNT', umount_prog.full_path())
      conf.set_quoted('MKFS', mkfs_prog.full_path())

      showmount_prog = find_program('showmount', required: false, dirs: libvirt_sbin_path)
      showmount_path = ''
      if showmount_prog.found()
        showmount_path = showmount_prog.full_path()
      endif
      conf.set_quoted('SHOWMOUNT', showmount_path)
    endif
  endif

  if not get_option('storage_gluster').disabled() and glusterfs_dep.found()
    use_storage = true
    conf.set('WITH_STORAGE_GLUSTER', 1)
  elif get_option('storage_gluster').enabled()
    error('Need glusterfs (libgfapi) for gluster storage driver')
  endif

  if not get_option('storage_iscsi').disabled() and iscsiadm_prog.found()
    use_storage = true
    conf.set('WITH_STORAGE_ISCSI', 1)
  elif get_option('storage_iscsi').enabled()
    error('We need iscsiadm for iSCSI storage driver')
  endif

  if not get_option('storage_iscsi_direct').disabled() and libiscsi_dep.found()
    use_storage = true
    conf.set('WITH_STORAGE_ISCSI_DIRECT', 1)
  elif get_option('storage_iscsi_direct').enabled()
    error('Need libiscsi for iscsi-direct storage driver')
  endif

  if not get_option('storage_lvm').disabled()
    lvm_enable = true
    lvm_progs = [
      'pvcreate', 'vgcreate', 'lvcreate',
      'pvremove', 'vgremove', 'lvremove',
      'lvchange', 'vgchange', 'vgscan',
      'pvs', 'vgs', 'lvs',
    ]
    foreach name : lvm_progs
      set_variable(
        '@0@_prog'.format(name),
        find_program(name, required: get_option('storage_lvm'), dirs: libvirt_sbin_path)
      )
      if not get_variable('@0@_prog'.format(name)).found()
        lvm_enable = false
      endif
    endforeach

    if lvm_enable
      use_storage = true
      conf.set('WITH_STORAGE_LVM', 1)

      foreach name : lvm_progs
        conf.set_quoted(name.to_upper(), get_variable('@0@_prog'.format(name)).full_path())
      endforeach
    endif
  endif

  if not get_option('storage_mpath').disabled() and host_machine.system() == 'linux' and devmapper_dep.found()
    use_storage = true
    conf.set('WITH_STORAGE_MPATH', 1)
  elif get_option('storage_mpath').enabled()
    error('mpath storage driver is supported only on Linux and you must install libdevmapper')
  endif

  if not get_option('storage_rbd').disabled() and rbd_dep.found()
    use_storage = true
    conf.set('WITH_STORAGE_RBD', 1)
  elif get_option('storage_rbd').enabled()
    error('You must install the librbd library & headers to compile libvirt')
  endif

  if not get_option('storage_scsi').disabled() and host_machine.system() == 'linux'
    use_storage = true
    conf.set('WITH_STORAGE_SCSI', 1)
  endif

  if not get_option('storage_vstorage').disabled()
    vstorage_enable = true
    if host_machine.system() != 'linux'
      vstorage_enable = false
      if get_option('storage_vstorage').enabled()
        error('Vstorage is supported only on Linux')
      endif
    endif

    if vstorage_enable
      use_storage = true
      conf.set('WITH_STORAGE_VSTORAGE', 1)
    endif
  endif

  if not get_option('storage_zfs').disabled()
    use_storage = true
    conf.set('WITH_STORAGE_ZFS', 1)
  endif
endif

if use_storage
  conf.set('WITH_STORAGE', 1)
endif


# build feature options

chrdev_lock_files = get_option('chrdev_lock_files')
if chrdev_lock_files == '' and host_machine.system() == 'linux'
  chrdev_lock_files = '/var/lock'
endif
if chrdev_lock_files != ''
  conf.set_quoted('VIR_CHRDEV_LOCK_FILE_PATH', chrdev_lock_files)
endif

driver_modules_flags = []
if conf.has('WITH_LIBVIRTD')
  if not conf.has('WITH_DLFCN_H') or not dlopen_dep.found()
    error('You must have dlfcn.h / dlopen() support to build driver modules')
  endif
  driver_modules_flags = libvirt_export_dynamic
endif

if host_machine.system() == 'linux'
  dtrace_prog = find_program('dtrace', required: get_option('dtrace'), dirs: libvirt_sbin_path)
  if dtrace_prog.found()
    conf.set('WITH_DTRACE_PROBES', 1)
  endif
  dtrace_command = [ 'env', 'CC=' + ' '.join(meson.get_compiler('c').cmd_array()), dtrace_prog ]
endif

if not get_option('host_validate').disabled() and host_machine.system() != 'windows'
  conf.set('WITH_HOST_VALIDATE', 1)
elif get_option('host_validate').enabled()
  error('virt-host-validate is not supported on Windows')
endif

if get_option('init_script') == 'check'
  if meson.is_cross_build()
    init_script = 'none'
  elif find_program('systemctl', required: false).found()
    init_script = 'systemd'
  elif find_program('openrc', required: false).found()
    init_script = 'openrc'
  else
    init_script = 'none'
  endif
else
  init_script = get_option('init_script')
endif

loader_nvram = get_option('loader_nvram')
if loader_nvram != ''
  if (loader_nvram.split(':').length() % 2) != 0
    error('Malformed loader_nvram option')
  endif
  conf.set_quoted('DEFAULT_LOADER_NVRAM', loader_nvram)
endif

if not get_option('login_shell').disabled() and host_machine.system() == 'linux'
  conf.set('WITH_LOGIN_SHELL', 1)
elif get_option('login_shell').enabled()
  error('virt-login-shell is supported on Linux only')
endif

if not get_option('nss').disabled()
  use_nss = true
  if not yajl_dep.found()
    if get_option('nss').enabled()
      error('Can\'t build nss plugin without yajl')
    else
      use_nss = false
    endif
  endif

  if use_nss and not conf.has('WITH_NETWORK')
    if get_option('nss').enabled()
      error('Can\'t build nss plugin without network')
    else
      use_nss = false
    endif
  endif

  if use_nss and not cc.check_header('nss.h')
    if get_option('nss').enabled()
      error('Can\'t build nss plugin without nss.h')
    else
      use_nss = false
    endif
  endif

  if use_nss
    conf.set('WITH_NSS', 1)

    if cc.has_type('struct gaih_addrtuple', prefix: '#include <nss.h>')
      conf.set('WITH_STRUCT_GAIH_ADDRTUPLE', 1)
    endif

    if (cc.has_type('ns_mtab', prefix: '#include <nsswitch.h>') and
        cc.has_type('nss_module_unregister_fn', prefix: '#include <nsswitch.h>'))
      conf.set('WITH_BSD_NSS', 1)
    endif
  endif
endif

if not get_option('numad').disabled() and numactl_dep.found()
  numad_prog = find_program('numad', required: get_option('numad'), dirs: libvirt_sbin_path)
  if numad_prog.found()
    conf.set('WITH_NUMAD', 1)
    conf.set_quoted('NUMAD', numad_prog.full_path())
  endif
elif get_option('numad').enabled()
  error('You must have numactl enabled for numad support.')
endif

# nwfilter should only be compiled for linux, and only if the
# libvirt daemon is also being compiled
if conf.has('WITH_LIBVIRTD') and host_machine.system() == 'linux'
  conf.set('WITH_NWFILTER', 1)
endif

if not get_option('pm_utils').disabled()
  use_pm_utils = true
  if init_script == 'systemd'
    use_pm_utils = false
  endif

  if use_pm_utils
    conf.set('WITH_PM_UTILS', 1)
  endif
endif

if not get_option('sysctl_config').disabled() and host_machine.system() == 'linux'
  conf.set('WITH_SYSCTL', 1)
elif get_option('sysctl_config').enabled()
  error('sysctl configuration is supported only on linux')
endif

conf.set_quoted('TLS_PRIORITY', get_option('tls_priority'))


# test options

tests_enabled = [ not get_option('tests').disabled() ]
if tests_enabled[0] and \
   cc.get_id() == 'clang' and \
   not supported_cc_flags.contains('-fsemantic-interposition') \
   and get_option('optimization') != '0'
   # If CLang doesn't support -fsemantic-interposition then our
   # mocking doesn't work. The best we can do is to not run the
   # test suite.
   msg = 'Forcibly disabling tests because CLang lacks -fsemantic-interposition. Update CLang or disable optimization'
   if get_option('tests').enabled()
     error(msg)
   endif
   tests_enabled = [ false, '!!! @0@ !!!'.format(msg) ]
endif

if get_option('expensive_tests').auto()
  use_expensive_tests = not git and tests_enabled[0]
else
  use_expensive_tests = get_option('expensive_tests').enabled()
  if use_expensive_tests and not tests_enabled[0]
    error('cannot enable expensive tests when tests are disabled')
  endif
endif

coverage_flags = []
if get_option('test_coverage')
  coverage_flags = [
    '-fprofile-arcs',
    '-ftest-coverage',
  ]
endif


# Various definitions

# Python3 < 3.7 treats the C locale as 7-bit only. We must force env vars so
# it treats it as UTF-8 regardless of the user's locale.
runutf8 = [ 'LC_ALL=', 'LANG=C', 'LC_CTYPE=en_US.UTF-8' ]


# define top include directory

top_inc_dir = include_directories('.')

keycodemapdb = subproject('keycodemapdb')

# include remaining subdirs

subdir('scripts')

subdir('include')

subdir('src')

subdir('tools')

if tests_enabled[0]
  subdir('tests')
else
  # Ensure that 'meson test' fails when tests are disabled, as opposed to
  # misleadingly succeeding at doing absolutely nothing
  test(
    'tests-are-disabled',
    python3_prog, args: [ '-c', 'raise Exception("tests are disabled")' ],
  )
endif

subdir('examples')

subdir('po')

gen_docs = not get_option('docs').disabled()
if gen_docs
  subdir('docs')
endif

subdir('build-aux')


# install pkgconfig files
pkgconfig_files = [
  'libvirt.pc.in',
  'libvirt-qemu.pc.in',
  'libvirt-lxc.pc.in',
  'libvirt-admin.pc.in',
]

pkgconfig_conf = configuration_data({
  'VERSION': meson.project_version(),
  'datadir': datadir,
  'datarootdir': datadir,
  'exec_prefix': prefix,
  'includedir': includedir,
  'libdir': libdir,
  'prefix': prefix,
})

pkgconfig_dir = libdir / 'pkgconfig'

foreach file : pkgconfig_files
  configure_file(
    input: file,
    output: '@BASENAME@',
    configuration: pkgconfig_conf,
    install: true,
    install_dir: pkgconfig_dir,
  )
endforeach


# generate dist files

if git
  spec_conf = configuration_data({
    'VERSION': meson.project_version(),
  })

  configure_file(
    input: 'libvirt.spec.in',
    output: '@BASENAME@',
    configuration: spec_conf,
  )

  authors = run_command(python3_prog, meson_gen_authors_prog.full_path(),
                        env: runutf8, check: true)
  authors_file = 'AUTHORS.rst.in'

  authors_conf = configuration_data({
    'contributorslist': authors.stdout(),
  })

  configure_file(
    input: authors_file,
    output: '@BASENAME@',
    configuration: authors_conf,
  )

  # Using return values from configure_file in add_dist_script is possible since 0.55.0
  dist_files = [
    'libvirt.spec',
    'AUTHORS.rst',
  ]

  foreach file : dist_files
    meson.add_dist_script(
      meson_python_prog.full_path(), python3_prog.full_path(), meson_dist_prog.full_path(),
      meson.project_build_root(), file
    )
  endforeach
endif


# generate meson-config.h file
configure_file(output: 'meson-config.h', configuration: conf)


# generate run helper
run_conf = configuration_data({
  'abs_builddir': meson.project_build_root(),
  'abs_top_builddir': meson.project_build_root(),
})

configure_file(
  input: 'run.in',
  output: '@BASENAME@',
  configuration: run_conf,
)
run_command('chmod', 'a+x', meson.current_build_dir() / 'run', check: true)


# print configuration summary

driver_summary = {
  'QEMU': conf.has('WITH_QEMU'),
  'OpenVZ': conf.has('WITH_OPENVZ'),
  'VMware': conf.has('WITH_VMWARE'),
  'VBox': conf.has('WITH_VBOX'),
  'libxl': conf.has('WITH_LIBXL'),
  'LXC': conf.has('WITH_LXC'),
  'Cloud-Hypervisor': conf.has('WITH_CH'),
  'ESX': conf.has('WITH_ESX'),
  'Hyper-V': conf.has('WITH_HYPERV'),
  'vz': conf.has('WITH_VZ'),
  'Bhyve': conf.has('WITH_BHYVE'),
  'Test': conf.has('WITH_TEST'),
  'Remote': conf.has('WITH_REMOTE'),
  'Network': conf.has('WITH_NETWORK'),
  'Libvirtd': conf.has('WITH_LIBVIRTD'),
  'Interface': conf.has('WITH_INTERFACE'),
}
summary(driver_summary, section: 'Drivers', bool_yn: true)

storagedriver_summary = {
  'Dir': conf.has('WITH_STORAGE_DIR'),
  'FS': conf.has('WITH_STORAGE_FS'),
  'NetFS': conf.has('WITH_STORAGE_FS'),
  'LVM': conf.has('WITH_STORAGE_LVM'),
  'iSCSI': conf.has('WITH_STORAGE_ISCSI'),
  'iscsi-direct': conf.has('WITH_STORAGE_ISCSI_DIRECT'),
  'SCSI': conf.has('WITH_STORAGE_SCSI'),
  'mpath': conf.has('WITH_STORAGE_MPATH'),
  'Disk': conf.has('WITH_STORAGE_DISK'),
  'RBD': conf.has('WITH_STORAGE_RBD'),
  'Gluster': conf.has('WITH_STORAGE_GLUSTER'),
  'ZFS': conf.has('WITH_STORAGE_ZFS'),
  'Virtuozzo storage': conf.has('WITH_STORAGE_VSTORAGE'),
}
summary(storagedriver_summary, section: 'Storage Drivers', bool_yn: true)

secdriver_summary = {
  'SELinux': conf.has('WITH_SECDRIVER_SELINUX'),
  'AppArmor': conf.has('WITH_SECDRIVER_APPARMOR'),
}
summary(secdriver_summary, section: 'Security Drivers', bool_yn: true)

drivermod_summary = {
  'driver_modules': driver_modules_flags.length() > 0,
}
summary(drivermod_summary, section: 'Driver Loadable Modules', bool_yn: true)

libs_summary = {
  'acl': acl_dep.found(),
  'apparmor': apparmor_dep.found(),
  'attr': attr_dep.found(),
  'audit': audit_dep.found(),
  'bash_completion': bash_completion_dep.found(),
  'blkid': blkid_dep.found(),
  'capng': capng_dep.found(),
  'curl': curl_dep.found(),
  'devmapper': devmapper_dep.found(),
  'dlopen': dlopen_dep.found(),
  'fuse': fuse_dep.found(),
  'glusterfs': glusterfs_dep.found(),
  'libiscsi': libiscsi_dep.found(),
  'libkvm': libkvm_dep.found(),
  'libnbd': libnbd_dep.found(),
  'libnl': libnl_dep.found(),
  'libparted': libparted_dep.found(),
  'libpcap': libpcap_dep.found(),
  'libssh': libssh_dep.found(),
  'libssh2': libssh2_dep.found(),
  'libutil': libutil_dep.found(),
  'netcf': netcf_dep.found(),
  'NLS': have_gnu_gettext_tools,
  'numactl': numactl_dep.found(),
  'openwsman': openwsman_dep.found(),
  'parallels-sdk': parallels_sdk_dep.found(),
  'pciaccess': pciaccess_dep.found(),
  'polkit': conf.has('WITH_POLKIT'),
  'rbd': rbd_dep.found(),
  'readline': readline_dep.found(),
  'sanlock': sanlock_dep.found(),
  'sasl': sasl_dep.found(),
  'selinux': selinux_dep.found(),
  'udev': udev_dep.found(),
  'xdr': xdr_dep.found(),
  'yajl': yajl_dep.found(),
}
summary(libs_summary, section: 'Libraries', bool_yn: true)

win_summary = {
  'MinGW': host_machine.system() == 'windows',
  'windres': host_machine.system() == 'windows',
}
summary(win_summary, section: 'Windows', bool_yn: true)

test_summary = {
  'Expensive': use_expensive_tests,
  'Coverage': coverage_flags.length() > 0,
}
summary(test_summary, section: 'Test suite', bool_yn: true)

if conf.has('DEFAULT_LOADER_NVRAM')
  loader_res = '@0@ !!! Using this configure option is strongly discouraged !!!'.format(conf.get_unquoted('DEFAULT_LOADER_NVRAM'))
else
  loader_res = ''
endif
misc_summary = {
  'Warning Flags': supported_cc_flags,
  'docs': gen_docs,
  'tests': tests_enabled,
  'DTrace': conf.has('WITH_DTRACE_PROBES'),
  'firewalld': conf.has('WITH_FIREWALLD'),
  'firewalld-zone': conf.has('WITH_FIREWALLD_ZONE'),
  'nss': conf.has('WITH_NSS'),
  'numad': conf.has('WITH_NUMAD'),
  'nbdkit': conf.has('WITH_NBDKIT'),
  'Init script': init_script,
  'Char device locks': chrdev_lock_files,
  'Loader/NVRAM': loader_res,
  'pm_utils': conf.has('WITH_PM_UTILS'),
  'virt-login-shell': conf.has('WITH_LOGIN_SHELL'),
  'virt-host-validate': conf.has('WITH_HOST_VALIDATE'),
  'TLS priority': conf.get_unquoted('TLS_PRIORITY'),
}
summary(misc_summary, section: 'Miscellaneous', bool_yn: true, list_sep: ' ')

devtools_summary = {
  'wireshark_dissector': wireshark_dep.found(),
}
summary(devtools_summary, section: 'Developer Tools', bool_yn: true)

if conf.has('WITH_QEMU')
  qemu_warn = ''
  if qemu_user == 'root'
    qemu_warn = ' !!! running QEMU as root is strongly discouraged !!!'
  endif
  priv_summary = {
    'QEMU': '@0@:@1@@2@'.format(qemu_user, qemu_group, qemu_warn),
  }
  summary(priv_summary, section: 'Privileges')
endif
