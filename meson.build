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


# check availability of various common functions (non-fatal if missing)

functions = [
  '__lxstat',
  '__lxstat64',
  '__xstat',
  '__xstat64',
  'elf_aux_info',
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
  'lstat',
  'lstat64',
  'mmap',
  'newlocale',
  'pipe2',
  'posix_fallocate',
  'posix_memalign',
  'prlimit',
  'sched_getaffinity',
  'sched_setscheduler',
  'setgroups',
  'setns',
  'setrlimit',
  'stat',
  'stat64',
  'symlink',
  'sysctlbyname',
  'unshare',
]

foreach function : functions
  if cc.has_function(function)
    conf.set('HAVE_@0@'.format(function.to_upper()), 1)
  endif
endforeach


# various header checks

headers = [
  'asm/hwcap.h',
  'ifaddrs.h',
  'libtasn1.h',
  'libutil.h',
  'linux/kvm.h',
  'linux/magic.h',
  'mntent.h',
  'net/ethernet.h',
  'net/if.h',
  'pty.h',
  'pwd.h',
  'stdarg.h',
  'sys/ioctl.h',
  'sys/mount.h',
  'sys/syscall.h',
  'sys/sysctl.h',
  'sys/ucred.h',
  'syslog.h',
  'util.h',
  'xlocale.h',
]

if host_machine.system() == 'linux'
  # check for kernel headers required by btrfs ioctl
  headers += 'linux/btrfs.h'
  # check for xfs dev headers required by xfs ioctl
  headers += 'xfs/xfs.h'
  # check for DEVLINK_CMD_ESWITCH_GET
  headers += 'linux/devlink.h'
endif

foreach name : headers
  if cc.has_header(name)
    conf.set('HAVE_@0@'.format(name.underscorify().to_upper()), 1)
  endif
endforeach

# check for kernel headers required by src/util/virnetdevbridge.c
if host_machine.system() == 'linux'
  # Various kernel versions have headers that are not self-standing, but
  # yet are incompatible with the corresponding glibc headers.  In order
  # to guarantee compilation across a wide range of versions (from RHEL 5
  # to rawhide), we first have to probe whether glibc and kernel can be
  # used in tandem; and if not, provide workarounds that ensure that
  # ABI-compatible IPv6 types are present for use by the kernel headers.
  netinet_workaround_code = '''
  #include <netinet/in.h>
  #include <linux/in6.h>

  int main(void) { return 0; }
  '''
  if not cc.compiles(netinet_workaround_code)
    conf.set('NETINET_LINUX_WORKAROUND', 1)
  endif

  required_headers = [
    'linux/param.h',
    'linux/sockios.h',
    'linux/if_bridge.h',
    'linux/if_tun.h',
  ]
  foreach name : required_headers
    if not cc.has_header(name)
      error('You must install kernel-headers in order to compile libvirt with QEMU or LXC support')
    endif
  endforeach
endif


# check various symbols

symbols = [
  # Check whether endian provides handy macros.
  [ 'endian.h', 'htole64' ],

  [ 'linux/ethtool.h', 'ETH_FLAG_TXVLAN' ],
  [ 'linux/ethtool.h', 'ETH_FLAG_NTUPLE' ],
  [ 'linux/ethtool.h', 'ETH_FLAG_RXHASH' ],
  [ 'linux/ethtool.h', 'ETH_FLAG_LRO' ],
  [ 'linux/ethtool.h', 'ETHTOOL_GGSO' ],
  [ 'linux/ethtool.h', 'ETHTOOL_GGRO' ],
  [ 'linux/ethtool.h', 'ETHTOOL_GFLAGS' ],
  [ 'linux/ethtool.h', 'ETHTOOL_GFEATURES' ],
  [ 'linux/ethtool.h', 'ETHTOOL_SCOALESCE' ],
  [ 'linux/ethtool.h', 'ETHTOOL_GCOALESCE' ],

  # GET_VLAN_VID_CMD is required for virNetDevGetVLanID
  [ 'linux/if_vlan.h', 'GET_VLAN_VID_CMD' ],

  [ 'unistd.h', 'SEEK_HOLE' ],

  # GET_VLAN_VID_CMD is required for virNetDevGetVLanID
  [ 'linux/if_vlan.h', 'GET_VLAN_VID_CMD' ],

  # Check for BSD approach for setting MAC addr
  [ 'net/if_dl.h', 'link_addr' ],
]

if host_machine.system() == 'linux'
  symbols += [
    # check for DEVLINK_CMD_ESWITCH_GET
    # Assume DEVLINK_ESWITCH_MODE_SWITCHDEV is also available, as it was
    # introudced in kernel 4.8 along with the original spelling of this
    # constant (DEVLINK_CMD_ESWITCH_MODE_GET, not supported by libvirt).
    [ 'linux/devlink.h', 'DEVLINK_CMD_ESWITCH_GET' ],

    # check for VHOST_VSOCK_SET_GUEST_CID
    [ 'linux/vhost.h', 'VHOST_VSOCK_SET_GUEST_CID' ],

    # Check if we have new enough kernel to support BPF devices for cgroups v2
    [ 'linux/bpf.h', 'BPF_PROG_QUERY' ],
    [ 'linux/bpf.h', 'BPF_CGROUP_DEVICE' ],
  ]
endif

foreach symbol : symbols
  if cc.has_header_symbol(symbol[0], symbol[1], args: '-D_GNU_SOURCE')
    conf.set('HAVE_DECL_@0@'.format(symbol[1].to_upper()), 1)
  endif
endforeach

# Check for BSD approach for bridge management
if (cc.has_header_symbol('net/if_bridgevar.h', 'BRDGSFD') and
    cc.has_header_symbol('net/if_bridgevar.h', 'BRDGADD') and
    cc.has_header_symbol('net/if_bridgevar.h', 'BRDGDEL'))
  conf.set('HAVE_BSD_BRIDGE_MGMT', 1)
endif

# Check for BSD CPU affinity availability
if cc.has_header_symbol('sys/cpuset.h', 'cpuset_getaffinity')
  conf.set('HAVE_BSD_CPU_AFFINITY', 1)
endif

# whether Mach clock routines are available
if (cc.has_header_symbol('mach/clock.h', 'clock_serv_t') and
    cc.has_header_symbol('mach/clock.h', 'host_get_clock_service') and
    cc.has_header_symbol('mach/clock.h', 'clock_get_time'))
  conf.set('HAVE_MACH_CLOCK_ROUTINES', 1)
endif


# check various types

types = [
  [ 'struct ifreq', '#include <sys/socket.h>\n#include <net/if.h>'] ,
  [ 'struct sockpeercred', '#include <sys/socket.h' ],
]

foreach type : types
  if cc.has_type(type[0], prefix: type[1])
    name = type[0].underscorify().to_upper()
    conf.set('HAVE_@0@'.format(name), 1)
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
    conf.set('HAVE_@0@_@1@'.format(type, member), 1)
  endif
endforeach


# check various types sizeof

conf.set('SIZEOF_LONG', cc.sizeof('long'))


# Where we look for daemons and admin binaries during configure

libvirt_sbin_path = [
  '/sbin',
  '/usr/sbin',
  '/usr/local/sbin',
]


# required programs check

required_programs = [
  'perl',
  'python3',
  'xmllint',
  'xsltproc',
]

required_programs_groups = [
  {'name':'rpcgen', 'prog':['rpcgen', 'portable-rpcgen']},
  # Drop the rst2html (aka HTML4) variants once we stop supporting Ubuntu 16.04 (Xenial)
  {'name':'rst2html', 'prog':['rst2html5', 'rst2html5.py', 'rst2html5-3', 'rst2html', 'rst2html.py', 'rst2html-3']},
  {'name':'rst2man', 'prog':['rst2man', 'rst2man.py', 'rst2man-3']},
]

if host_machine.system() == 'freebsd'
  required_programs += 'ifconfig'
endif

foreach name : required_programs
  prog = find_program(name, required: true, dirs: libvirt_sbin_path)
  varname = name.underscorify()
  conf.set_quoted(varname.to_upper(), prog.path())
  set_variable('@0@_prog'.format(varname), prog)
endforeach

foreach item : required_programs_groups
  prog = find_program(item.get('prog'), required: true, dirs: libvirt_sbin_path)
  varname = item.get('name').underscorify()
  conf.set_quoted(varname.to_upper(), prog.path())
  set_variable('@0@_prog'.format(varname), prog)
endforeach


# optional programs

optional_programs = [
  'addr2line',
  'augparse',
  'dmidecode',
  'dnsmasq',
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
  'radvd',
  'rmmod',
  'scrub',
  'tc',
  'udevadm',
]

foreach name : optional_programs
  prog = find_program(name, required: false, dirs: libvirt_sbin_path)
  varname = name.underscorify()
  if prog.found()
    prog_path = prog.path()
  else
    prog_path = name
  endif

  conf.set_quoted(varname.to_upper(), prog_path)
  conf.set_quoted('@0@_PATH'.format(varname.to_upper()), prog_path)
  set_variable('@0@_prog'.format(varname), prog)
endforeach


# generic build dependencies

if host_machine.system() == 'linux' and cc.has_header('sys/acl.h')
  acl_dep = cc.find_library('acl', required: false)
  conf.set('HAVE_SYS_ACL_H', 1)
else
  acl_dep = dependency('', required: false)
endif

apparmor_dep = dependency('libapparmor', required: get_option('apparmor'))
if apparmor_dep.found()
  conf.set('WITH_APPARMOR', 1)
  conf.set_quoted('APPARMOR_DIR', '/etc/apparmor.d')
  conf.set_quoted('APPARMOR_PROFILES_PATH', '/sys/kernel/security/apparmor/profiles')
endif

attr_dep = cc.find_library('attr', required: get_option('attr'))
if attr_dep.found()
  conf.set('HAVE_LIBATTR', 1)
endif

audit_dep = cc.find_library('audit', required: get_option('audit'))
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

capng_dep = cc.find_library('cap-ng', required: get_option('capng'))
if capng_dep.found()
  conf.set('WITH_CAPNG', 1)
endif

curl_version = '7.18.0'
curl_dep = dependency('libcurl', version: '>=' + curl_version, required: get_option('curl'))
if curl_dep.found()
  # XXX as of libcurl-devel-7.20.1-3.fc13.x86_64, curl ships a version
  # of <curl/curl.h> that #defines several wrapper macros around underlying
  # functions to add type safety for gcc only.  However, these macros
  # spuriously trip gcc's -Wlogical-op warning.  Avoid the warning by
  # disabling the wrappers; even if it removes some type-check safety.
  curl_dep = declare_dependency(
    compile_args: [ '-DCURL_DISABLE_TYPECHECK' ],
    dependencies: [ curl_dep ],
  )

  conf.set('WITH_CURL', 1)
endif

dbus_version = '1.0.0'
dbus_dep = dependency('dbus-1', version: '>=' + dbus_version, required: get_option('dbus'))
if dbus_dep.found()
  conf.set('WITH_DBUS', 1)

  function = 'dbus_watch_get_unix_fd'
  if cc.has_function(function, dependencies: dbus_dep)
    conf.set('HAVE_@0@'.format(function.to_upper()), 1)
  endif

  type = 'DBusBasicValue'
  if cc.has_type(type, dependencies: dbus_dep, prefix: '#include <dbus/dbus.h>')
    conf.set('HAVE_@0@'.format(type.to_upper()), 1)
  endif
endif

devmapper_version = '1.0.0'
devmapper_dep = dependency('devmapper', version: '>=' + devmapper_version, required: false)
if not devmapper_dep.found()
  # devmapper is missing pkg-config files in ubuntu, suse, etc
  devmapper_dep = cc.find_library('devmapper', required: false)
  if devmapper_dep.found() and not cc.has_function('dm_task_run', dependencies: tmp)
    devmapper_dep = dependency('', required: false)
  endif
endif
if devmapper_dep.found()
  conf.set('WITH_DEVMAPPER', 1)
endif

dlopen_use = host_machine.system() != 'windows'
dlopen_dep = cc.find_library('dl', required: dlopen_use)
if dlopen_dep.found()
  if not cc.has_header('dlfcn.h')
    error('Unable to find dlfcn.h')
  endif
  conf.set('HAVE_DLFCN_H', 1)
endif

fuse_version = '2.8.6'
fuse_dep = dependency('fuse', version: '>=' + fuse_version, required: get_option('fuse'))
if fuse_dep.found()
  conf.set('WITH_FUSE', 1)
endif

glib_version = '2.48.0'
glib_dep = dependency('glib-2.0', version: '>=' + glib_version)
gobject_dep = dependency('gobject-2.0', version: '>=' + glib_version)
gio_dep = dependency('gio-2.0', version: '>=' + glib_version)
glib_dep = declare_dependency(
  dependencies: [ glib_dep, gobject_dep, gio_dep ],
)

glusterfs_version = '3.4.1'
glusterfs_dep = dependency('glusterfs-api', version: '>=' + glusterfs_version, required: get_option('glusterfs'))

gnutls_version = '3.2.0'
gnutls_dep = dependency('gnutls', version: '>=' + gnutls_version)

hal_version = '0.5.0'
hal_dep = dependency('hal', version: '>=' + hal_version, required: get_option('hal'))
if hal_dep.found()
  conf.set('WITH_HAL', 1)
endif

# Check for BSD kvm (kernel memory interface)
if host_machine.system() == 'freebsd'
  kvm_dep = cc.find_library('kvm')
  add_project_link_arguments('-lkvm', language: 'c')
endif

libiscsi_version = '1.18.0'
libiscsi_dep = dependency('libiscsi', version: '>=' + libiscsi_version, required: get_option('libiscsi'))

use_macvtap = false
if not get_option('macvtap').disabled()
  if (cc.has_header_symbol('linux/if_link.h', 'MACVLAN_MODE_BRIDGE') and
      cc.has_header_symbol('linux/if_link.h', 'IFLA_VF_MAX'))
    use_macvtap = true
  endif

  if get_option('macvtap').enabled() and not use_macvtap
    error('Installed linux headers don\'t show support for macvtap device.')
  endif
endif
if use_macvtap
  conf.set('WITH_MACVTAP', 1)

  if cc.has_header_symbol('linux/if_link.h', 'MACVLAN_MODE_PASSTHRU')
    conf.set('HAVE_DECL_MACVLAN_MODE_PASSTHRU', 1)
  endif
endif

# readline 7.0 is the first version which includes pkg-config support
readline_version = '7.0'
readline_dep = dependency('readline', version: '>=' + readline_version, required: false)
if not readline_dep.found()
  readline_dep = cc.find_library('readline', required: get_option('readline'))

  if readline_dep.found()
    # This function is present in all reasonable (5.0+) readline versions;
    # however, the macOS base system contains a library called libedit which
    # takes over the readline name despite lacking many of its features. We
    # want to make sure we only enable readline support when linking against
    # the actual readline library, and the availability of this specific
    # functions is as good a witness for that fact as any.
    correct_rl = cc.has_function('rl_completion_quote_character', prefix: '#include <readline/readline.h>')
    if not correct_rl and get_option('readline').enabled()
      error('readline is missing rl_completion_quote_character')
    else
      readline_dep = dependency('', required: false)
    endif
  endif
endif
if readline_dep.found()
  # Gross kludge for readline include path obtained through pkg-config.
  #
  # As of 8.0, upstream readline.pc has -I${includedir}/readline among
  # its Cflags, which is clearly wrong. This does not affect Linux
  # because ${includedir} is already part of the default include path,
  # but on other platforms that's not the case and the result is that
  # <readline/readline.h> can't be located, causing the build to fail.
  # A patch solving this issue has already been posted upstream, so once
  # the fix has landed in FreeBSD ports and macOS homebrew we can safely
  # drop the kludge and rely on pkg-config alone on those platforms.
  #
  # [1] http://lists.gnu.org/archive/html/bug-readline/2019-04/msg00007.html
  if readline_dep.type_name() == 'pkgconfig' and host_machine.system() != 'linux'
    pkg_config_prog = find_program('pkg-config')
    rc = run_command(pkg_config_prog, '--cflags', 'readline', check: true)
    cflags = rc.stdout().strip()
    if cflags.contains('include/readline')
      rc = run_command(
        'python3', '-c',
        'print("@0@".replace("@1@", "@2@"))'.format(
          cflags, 'include/readline', 'include',
        ),
        check: true,
      )
      readline_dep = declare_dependency(
        compile_args: rc.stdout().strip().split(),
        dependencies: [ readline_dep ],
      )
    endif
  endif

  # We need this to avoid compilation issues with modern compilers.
  # See 9ea3424a178 for a more detailed explanation
  readline_dep = declare_dependency(
    compile_args: [ '-D_FUNCTION_DEF' ],
    dependencies: [ readline_dep ],
  )

  conf.set('WITH_READLINE', 1)
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
    bash_completion_dir = bash_completion_dep.get_pkgconfig_variable('completionsdir')
    bash_completion_prefix = bash_completion_dep.get_pkgconfig_variable('prefix')
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

if host_machine.system() != 'freebsd'
  if not get_option('firewalld').disabled() and dbus_dep.found()
    conf.set('WITH_FIREWALLD', 1)
  elif get_option('firewalld').enabled()
    error('You must have dbus enabled for firewalld support')
  endif
endif

if not get_option('firewalld_zone').disabled() and conf.has('WITH_FIREWALLD')
  conf.set('WITH_FIREWALLD_ZONE', 1)
elif get_option('firewalld_zone').enabled()
  error('You must have firewalld support enabled to enable firewalld_zone')
endif


# define top include directory

top_inc_dir = include_directories('.')


# include remaining subdirs

subdir('scripts')

subdir('include')


# generate meson-config.h file
configure_file(output: 'meson-config.h', configuration: conf)


# print configuration summary

libs_summary = {
  'acl': acl_dep.found(),
  'apparmor': apparmor_dep.found(),
  'attr': attr_dep.found(),
  'audit': audit_dep.found(),
  'bash_completion': bash_completion_dep.found(),
  'blkid': blkid_dep.found(),
  'capng': capng_dep.found(),
  'curl': curl_dep.found(),
  'dbus': dbus_dep.found(),
  'dlopen': dlopen_dep.found(),
  'firewalld': conf.has('WITH_FIREWALLD'),
  'firewalld-zone': conf.has('WITH_FIREWALLD_ZONE'),
  'fuse': fuse_dep.found(),
  'glib_dep': glib_dep.found(),
  'glusterfs': glusterfs_dep.found(),
  'gnutls': gnutls_dep.found(),
  'hal': hal_dep.found(),
  'libiscsi': libiscsi_dep.found(),
  'macvtap': conf.has('WITH_MACVTAP'),
  'readline': readline_dep.found(),
}
summary(libs_summary, section: 'Libraries', bool_yn: true)

test_summary = {
  'Coverage': coverage_flags.length() > 0,
}
summary(test_summary, section: 'Test suite', bool_yn: true)

misc_summary = {
  'Use -Werror': cc_flags.contains('-Werror'),
  'Warning Flags': supported_cc_flags,
}
summary(misc_summary, section: 'Miscellaneous', bool_yn: true, list_sep: ' ')
