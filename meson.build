project(
  'libvirt', 'c',
  version: '7.0.0',
  license: 'LGPLv2+',
  meson_version: '>= 0.54.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_pie=true',
    'c_std=gnu99',
    'warning_level=2',
  ],
)


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
  '-Wall',
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
  '-Wextra',
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

  # Clang incorrectly complains about dup typedefs win gnu99 mode
  # so use this Clang-specific arg to keep it quiet
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
  conf.set('WITH_SUGGEST_ATTRIBUTE_FORMAT', 1)
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
  'linux/magic.h',
  'mntent.h',
  'net/ethernet.h',
  'net/if.h',
  'pty.h',
  'pwd.h',
  'sys/ioctl.h',
  'sys/mount.h',
  'sys/syscall.h',
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

if host_machine.system() == 'freebsd'
  headers += 'libutil.h'
endif

foreach name : headers
  if cc.has_header(name)
    conf.set('WITH_@0@'.format(name.underscorify().to_upper()), 1)
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

  # Check for BSD approach for setting MAC addr
  [ 'net/if_dl.h', 'link_addr', '#include <sys/types.h>\n#include <sys/socket.h>' ],
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
if cc.has_header_symbol('sys/cpuset.h', 'cpuset_getaffinity')
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
  {'name':'rst2html', 'prog':['rst2html5', 'rst2html5.py', 'rst2html5-3']},
  {'name':'rst2man', 'prog':['rst2man', 'rst2man.py', 'rst2man-3']},
]

if host_machine.system() == 'freebsd'
  required_programs += 'ifconfig'
endif

foreach name : required_programs
  prog = find_program(name, required: true, dirs: libvirt_sbin_path)
  varname = name.underscorify()
  conf.set_quoted(varname.to_upper(), prog.path())
  conf.set_quoted('@0@_PATH'.format(varname.to_upper()), prog.path())
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
  'pdwtags',
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
  conf.set('WITH_SYS_ACL_H', 1)
else
  acl_dep = dependency('', required: false)
endif

apparmor_dep = dependency('libapparmor', required: get_option('apparmor'))
if apparmor_dep.found()
  if get_option('apparmor_profiles')
    conf.set('WITH_APPARMOR_PROFILES', 1)
  endif
  conf.set('WITH_APPARMOR', 1)
  conf.set_quoted('APPARMOR_DIR', sysconfdir / 'apparmor.d')
  conf.set_quoted('APPARMOR_PROFILES_PATH', '/sys/kernel/security/apparmor/profiles')
endif

attr_dep = cc.find_library('attr', required: get_option('attr'))
if attr_dep.found()
  conf.set('WITH_LIBATTR', 1)
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

devmapper_version = '1.0.0'
devmapper_dep = dependency('devmapper', version: '>=' + devmapper_version, required: false)
if devmapper_dep.found()
  conf.set('WITH_DEVMAPPER', 1)
endif

dlopen_use = host_machine.system() != 'windows'
dlopen_dep = cc.find_library('dl', required: dlopen_use)
if dlopen_dep.found()
  if not cc.has_header('dlfcn.h')
    error('Unable to find dlfcn.h')
  endif
  conf.set('WITH_DLFCN_H', 1)
endif

fuse_version = '2.8.6'
fuse_dep = dependency('fuse', version: '>=' + fuse_version, required: get_option('fuse'))
if fuse_dep.found()
  conf.set('WITH_FUSE', 1)
endif

glib_version = '2.48.0'
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

glusterfs_version = '3.4.1'
glusterfs_dep = dependency('glusterfs-api', version: '>=' + glusterfs_version, required: get_option('glusterfs'))

gnutls_version = '3.2.0'
gnutls_dep = dependency('gnutls', version: '>=' + gnutls_version)

# Check for BSD kvm (kernel memory interface)
if host_machine.system() == 'freebsd'
  libkvm_dep = cc.find_library('kvm')
else
  libkvm_dep = dependency('', required: false)
endif

libiscsi_version = '1.18.0'
libiscsi_dep = dependency('libiscsi', version: '>=' + libiscsi_version, required: get_option('libiscsi'))

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
libparted_dep = dependency('libparted', version: '>=' + libparted_version, required: false)
if libparted_dep.found()
  parted_prog = find_program('parted', required: false, dirs: libvirt_sbin_path)
  if parted_prog.found()
    conf.set_quoted('PARTED', parted_prog.path())
  else
    libparted_dep = dependency('', required: false)
  endif
endif

libpcap_version = '1.5.0'
if not get_option('libpcap').disabled()
  libpcap_dep = dependency('libpcap', version: '>=' + libpcap_version, required: false)

  if not libpcap_dep.found()
    pcap_config_prog = find_program('pcap-config', required: get_option('libpcap'))
    if pcap_config_prog.found()
      pcap_args = run_command(pcap_config_prog, '--cflags').stdout().strip().split()
      pcap_libs = run_command(pcap_config_prog, '--libs').stdout().strip().split()
      libpcap_dep = declare_dependency(
        compile_args: pcap_args,
        link_args: pcap_libs,
      )
    endif
  endif
else
  libpcap_dep = dependency('', required: false)
endif
if libpcap_dep.found()
  conf.set('WITH_LIBPCAP', 1)
endif

libssh_version = '0.7'
if get_option('driver_remote').enabled()
  libssh_dep = dependency('libssh', version: '>=' + libssh_version, required: get_option('libssh'))
  if libssh_dep.found()
    conf.set('WITH_LIBSSH', 1)

    # Check if new functions exists, if not redefine them with old deprecated ones.
    # List of [ new_function, deprecated_function ].
    functions = [
      [ 'ssh_get_server_publickey', 'ssh_get_publickey' ],
      [ 'ssh_session_is_known_server', 'ssh_is_server_known' ],
      [ 'ssh_session_update_known_hosts', 'ssh_write_knownhost' ],
    ]
    foreach name : functions
      if not cc.has_function(name[0], dependencies: libssh_dep)
        conf.set(name[0], name[1])
      endif
    endforeach
  endif
else
  libssh_dep = dependency('', required: false)
endif

libssh2_version = '1.3'
if get_option('driver_remote').enabled()
  libssh2_dep = dependency('libssh2', version: '>=' + libssh2_version, required: get_option('libssh2'))
  if libssh2_dep.found()
    conf.set('WITH_SSH2', 1)
  endif
else
  libssh2_dep = dependency('', required: false)
endif

libxml_version = '2.9.1'
libxml_dep = dependency('libxml-2.0', version: '>=' + libxml_version)

libm_dep = cc.find_library('m', required : false)

netcf_version = '0.1.8'
netcf_dep = dependency('netcf', version: '>=' + netcf_version, required: get_option('netcf'))
if netcf_dep.found()
  conf.set('WITH_NETCF', 1)
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

  if cc.has_header('libintl.h')
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
    rc = run_command(msgfmt_prog, '--version')
    if rc.returncode() == 0 and rc.stdout().contains('GNU gettext')
      have_gnu_gettext_tools = true
    endif
  endif
else
  intl_dep = dependency('', required: false)
endif

numactl_version = '2.0.6'
numactl_dep = cc.find_library('numa', required: get_option('numactl'))
if numactl_dep.found()
  conf.set('WITH_NUMACTL', 1)
endif

openwsman_version = '2.6.3'
openwsman_dep = dependency('openwsman', version: '>=' + openwsman_version, required: get_option('openwsman'))

parallels_sdk_version = '7.0.22'
parallels_sdk_dep = dependency('parallels-sdk', version: '>=' + parallels_sdk_version, required: false)

pciaccess_version = '0.10.0'
pciaccess_dep = dependency('pciaccess', version: '>=' + pciaccess_version, required: get_option('pciaccess'))

if not get_option('polkit').disabled() and host_machine.system() != 'windows'
  pkcheck_prog = find_program('pkcheck', required: false, dirs: libvirt_sbin_path)
else
  pkcheck_prog = dependency('', required: false)
endif

rbd_dep = cc.find_library('rbd', required: false)
rados_dep = cc.find_library('rados', required: false)
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
else
  readline_dep = dependency('', required: false)
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
  # [1] https://lists.gnu.org/archive/html/bug-readline/2019-04/msg00007.html
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

if not get_option('sanlock').disabled()
  sanlock_dep = dependency('libsanlock_client', required: false)

  if sanlock_dep.found()
    conf.set('WITH_SANLOCK', 1)
    # check for sanlock_strerror introduced in sanlock-3.5.0
    if cc.has_function('sanlock_strerror', dependencies: sanlock_dep)
      conf.set('WITH_SANLOCK_STRERROR', 1)
    endif
  endif
endif

sasl_version = '2.1.26'
if get_option('driver_remote').enabled()
  sasl_dep = dependency('libsasl2', version: '>=' + sasl_version, required: get_option('sasl'))
  if sasl_dep.found()
    conf.set('WITH_SASL', 1)
  endif
else
  sasl_dep = dependency('', required: false)
endif

selinux_dep = cc.find_library('selinux', required: get_option('selinux'))
if selinux_dep.found()
  selinux_mount = get_option('selinux_mount')
  if selinux_mount == ''
    if run_command('test', '-d', '/sys/fs/selinux').returncode() == 0
      selinux_mount = '/sys/fs/selinux'
    else
      selinux_mount = '/selinux'
    endif
  endif
  conf.set_quoted('SELINUX_MOUNT', selinux_mount)
  conf.set('WITH_SELINUX', 1)
endif

thread_dep = dependency('threads', required: true)
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
  wireshark_plugindir = get_option('wireshark_plugindir')
  if wireshark_plugindir == ''
    wireshark_plugindir = wireshark_dep.get_pkgconfig_variable('plugindir')
  endif

  wireshark_prefix = wireshark_dep.get_pkgconfig_variable('prefix')
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
  if cc.has_header('wireshark/ws_version.h')
    conf.set('WITH_WS_VERSION', 1)
  endif
endif

# On MinGW portablexdr provides XDR functions, on linux they are
# provided by libtirpc and on FreeBSD/macOS there is no need to
# use extra library as it's provided by libc directly.
if host_machine.system() == 'windows'
  xdr_dep = cc.find_library('portablexdr', required: false)
elif host_machine.system() == 'linux'
  xdr_dep = dependency('libtirpc', required: false)
else
  xdr_dep = declare_dependency()
endif

yajl_version = '2.0.3'
yajl_dep = dependency('yajl', version: '>=' + yajl_version, required: get_option('yajl'))
if yajl_dep.found()
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
  if not get_option('firewalld').disabled()
    conf.set('WITH_FIREWALLD', 1)
  endif
endif

if not get_option('firewalld_zone').disabled() and conf.has('WITH_FIREWALLD')
  conf.set('WITH_FIREWALLD_ZONE', 1)
elif get_option('firewalld_zone').enabled()
  error('You must have firewalld support enabled to enable firewalld_zone')
endif

if (pkcheck_prog.found() or get_option('polkit').enabled())
  conf.set('WITH_POLKIT', 1)
endif

if udev_dep.found() and not pciaccess_dep.found()
  error('You must install the pciaccess module to build with udev')
endif


# build driver options

if get_option('driver_remote').enabled()
  if not xdr_dep.found() and host_machine.system() not in [ 'freebsd', 'darwin' ]
    error('XDR is required for remote driver')
  endif
  conf.set('WITH_REMOTE', 1)
endif

remote_default_mode = get_option('remote_default_mode').to_upper()
conf.set('REMOTE_DRIVER_MODE_DEFAULT', 'REMOTE_DRIVER_MODE_@0@'.format(remote_default_mode))

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
    conf.set_quoted('BHYVE', bhyve_prog.path())
    conf.set_quoted('BHYVECTL', bhyvectl_prog.path())
    conf.set_quoted('BHYVELOAD', bhyveload_prog.path())
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

if not get_option('driver_interface').disabled() and conf.has('WITH_LIBVIRTD') and (udev_dep.found() or netcf_dep.found())
  conf.set('WITH_INTERFACE', 1)
elif get_option('driver_interface').enabled()
  error('Requested the Interface driver without netcf or udev and libvirtd support')
endif

if not get_option('driver_libxl').disabled() and conf.has('WITH_LIBVIRTD')
  libxl_version = '4.6.0'
  libxl_dep = dependency('xenlight', version: '>=' + libxl_version, required: get_option('driver_libxl'))

  if libxl_dep.found()
    libxl_firmware_dir = libxl_dep.get_pkgconfig_variable('xenfirmwaredir')
    libxl_execbin = libxl_dep.get_pkgconfig_variable('libexec_bin')
    if libxl_firmware_dir != ''
      conf.set_quoted('LIBXL_FIRMWARE_DIR', libxl_firmware_dir)
    endif
    if libxl_execbin != ''
      conf.set_quoted('LIBXL_EXECBIN_DIR', libxl_execbin)
    endif

    # If building with libxl, use the libxl utility header and lib too
    if cc.has_header('libxlutil.h')
      conf.set('WITH_LIBXLUTIL_H', 1)
    endif
    xl_util_dep = cc.find_library('xlutil')

    xen_store_dep = cc.find_library('xenstore')

    # xtl_* infrastructure is in libxentoollog since Xen 4.7 previously
    # it was in libxenctrl.
    if libxl_dep.version().version_compare('>=4.7.0')
      xtl_link_dep = cc.find_library('xentoollog')
    else
      xtl_link_dep = cc.find_library('xenctrl')
    endif

    libxl_dep = declare_dependency(
      compile_args: '-DLIBXL_API_VERSION=0x040500',
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
  lxc_support_code = '''
#include <sched.h>
#include <linux/loop.h>
#include <sys/epoll.h>

void main(void) {
    unshare(!(LO_FLAGS_AUTOCLEAR + EPOLL_CLOEXEC));
}
  '''
  if cc.compiles(lxc_support_code, name: 'lxc support', args: '-D_GNU_SOURCE')
    conf.set('WITH_LXC', 1)
    conf.set('WITH_DECL_LO_FLAGS_AUTOCLEAR', 1)
  elif get_option('driver_lxc').enabled()
    error('Required kernel features for LXC were not found')
  endif

  lxc_get_free_code = '''
#include <sched.h>
#include <linux/loop.h>
#include <sys/epoll.h>

void main(void) {
    unshare(!(LOOP_CTL_GET_FREE));
}
  '''
  if cc.compiles(lxc_get_free_code)
    conf.set('WITH_DECL_LOOP_CTL_GET_FREE', 1)
  endif
elif get_option('driver_lxc').enabled()
  error('linux and remote_driver are required for LXC')
endif

# there's no use compiling the network driver without the libvirt
# daemon, nor compiling it for macOS, where it breaks the compile
if not get_option('driver_network').disabled() and conf.has('WITH_LIBVIRTD') and host_machine.system() != 'darwin'
  conf.set('WITH_NETWORK', 1)
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
      qemu_moddir = '/usr' / libdir / 'qemu'
    endif
    conf.set_quoted('QEMU_MODDIR', qemu_moddir)

    if host_machine.system() in ['freebsd', 'darwin']
      default_qemu_user = 'root'
      default_qemu_group = 'wheel'
    else
      os_release = run_command('grep', '^ID=', '/etc/os-release').stdout()
      if os_release.contains('arch')
        default_qemu_user = 'nobody'
        default_qemu_group = 'nobody'
      elif (os_release.contains('centos') or
            os_release.contains('fedora') or
            os_release.contains('gentoo') or
            os_release.contains('rhel') or
            os_release.contains('suse'))
        default_qemu_user = 'qemu'
        default_qemu_group = 'qemu'
      elif os_release.contains('debian')
        default_qemu_user = 'libvirt-qemu'
        default_qemu_group = 'libvirt-qemu'
      elif os_release.contains('ubuntu')
        default_qemu_user = 'libvirt-qemu'
        default_qemu_group = 'kvm'
      else
        default_qemu_user = 'root'
        default_qemu_group = 'root'
      endif
      # If the expected user and group don't exist, or we haven't hit any
      # of the cases above bacuse we're running on an unknown OS, the only
      # sensible fallback is root:root
      if (run_command('getent', 'passwd', default_qemu_user).returncode() != 0 and
          run_command('getent', 'group', default_qemu_group).returncode() != 0)
        default_qemu_user = 'root'
        default_qemu_group = 'root'
      endif
    endif
    qemu_user = get_option('qemu_user')
    if qemu_user == ''
      qemu_user = default_qemu_user
    endif
    qemu_group = get_option('qemu_group')
    if qemu_group == ''
      qemu_group = default_qemu_group
    endif
    conf.set_quoted('QEMU_USER', qemu_user)
    conf.set_quoted('QEMU_GROUP', qemu_group)

    qemu_bridge_prog = find_program(
      'qemu-bridge-helper',
      dirs: [ '/usr/libexec', '/usr/lib/qemu', '/usr/lib' ],
      required: false
    )
    if qemu_bridge_prog.found()
      qemu_bridge_path = qemu_bridge_prog.path()
    else
      qemu_bridge_path = '/usr/libexec/qemu-bridge-helper'
    endif
    conf.set_quoted('QEMU_BRIDGE_HELPER', qemu_bridge_path)

    qemu_pr_prog = find_program(
      'qemu-pr-helper',
      dirs: [ '/usr/bin', '/usr/libexec' ],
      required: false
    )
    if qemu_pr_prog.found()
      qemu_pr_path = qemu_pr_prog.path()
    else
      qemu_pr_path = '/usr/bin/qemu-pr-helper'
    endif
    conf.set_quoted('QEMU_PR_HELPER', qemu_pr_path)

    qemu_slirp_prog = find_program(
      'slirp-helper',
      dirs: [ '/usr/bin', '/usr/libexec' ],
      required: false
    )
    if qemu_slirp_prog.found()
      qemu_slirp_path = qemu_slirp_prog.path()
    else
      qemu_slirp_path = '/usr/bin/slirp-helper'
    endif
    conf.set_quoted('QEMU_SLIRP_HELPER', qemu_slirp_path)

    qemu_dbus_daemon_prog = find_program(
      'dbus-daemon',
      dirs: [ '/usr/bin', '/usr/libexec' ],
      required: false
    )
    if qemu_dbus_daemon_prog.found()
      qemu_dbus_daemon_path = qemu_dbus_daemon_prog.path()
    else
      qemu_dbus_daemon_path = '/usr/bin/dbus-daemon'
    endif
    conf.set_quoted('QEMU_DBUS_DAEMON', qemu_dbus_daemon_path)
  endif
endif

if not get_option('driver_secrets').disabled() and conf.has('WITH_LIBVIRTD')
  conf.set('WITH_SECRETS', 1)
endif

if get_option('driver_test').enabled()
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

    if fs_enable and not cc.has_header('mntent.h')
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
      conf.set_quoted('MOUNT', mount_prog.path())
      conf.set_quoted('UMOUNT', umount_prog.path())
      conf.set_quoted('MKFS', mkfs_prog.path())

      showmount_prog = find_program('showmount', required: false, dirs: libvirt_sbin_path)
      showmount_path = ''
      if showmount_prog.found()
        showmount_path = showmount_prog.path()
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
        conf.set_quoted(name.to_upper(), get_variable('@0@_prog'.format(name)).path())
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

  if not get_option('storage_sheepdog').disabled()
    sheepdogcli_prog = find_program(['collie', 'dog'], required: get_option('storage_sheepdog'), dirs: libvirt_sbin_path)

    if sheepdogcli_prog.found()
      use_storage = true
      conf.set('WITH_STORAGE_SHEEPDOG', 1)
      conf.set_quoted('SHEEPDOGCLI', sheepdogcli_prog.path())
    endif
  endif

  if not get_option('storage_vstorage').disabled()
    vstorage_enable = true

    foreach name : ['vstorage', 'vstorage-mount', 'umount']
      set_variable(
        '@0@_prog'.format(name.underscorify()),
        find_program(name, required: get_option('storage_vstorage'), dirs: libvirt_sbin_path)
      )
      if not get_variable('@0@_prog'.format(name.underscorify())).found()
        vstorage_enable = false
      endif
    endforeach

    if vstorage_enable
      use_storage = true
      conf.set('WITH_STORAGE_VSTORAGE', 1)
      foreach name : ['vstorage', 'vstorage-mount', 'umount']
        path = get_variable('@0@_prog'.format(name.underscorify())).path()
        conf.set_quoted(name.to_upper(), path)
      endforeach
    endif
  endif

  if not get_option('storage_zfs').disabled()
    zfs_enable = true
    foreach name : ['zfs', 'zpool']
      set_variable(
        '@0@_prog'.format(name),
        find_program(name, required: get_option('storage_zfs'), dirs: libvirt_sbin_path)
      )
      if not get_variable('@0@_prog'.format(name)).found()
        zfs_enable = false
      endif
    endforeach

    if zfs_enable
      use_storage = true
      conf.set('WITH_STORAGE_ZFS', 1)
      foreach name : ['zfs', 'zpool']
        conf.set_quoted(name.to_upper(), get_variable('@0@_prog'.format(name)).path())
      endforeach
    endif
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

  if use_nss and not cc.has_header('nss.h')
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
    conf.set_quoted('NUMAD', numad_prog.path())
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


# Various definitions

# Python3 < 3.7 treats the C locale as 7-bit only. We must force env vars so
# it treats it as UTF-8 regardless of the user's locale.
runutf8 = [ 'LC_ALL=', 'LANG=C', 'LC_CTYPE=en_US.UTF-8' ]


# define top include directory

top_inc_dir = include_directories('.')


# include remaining subdirs

subdir('scripts')

subdir('include')

subdir('src')

subdir('tools')

build_tests = not get_option('tests').disabled()
if build_tests
  subdir('tests')
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

pkgconfig_conf = configuration_data()
pkgconfig_conf.set('VERSION', meson.project_version())
pkgconfig_conf.set('datadir', datadir)
pkgconfig_conf.set('datarootdir', datadir)
pkgconfig_conf.set('exec_prefix', prefix)
pkgconfig_conf.set('includedir', includedir)
pkgconfig_conf.set('libdir', libdir)
pkgconfig_conf.set('prefix', prefix)

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
  spec_files = [
    'libvirt.spec.in',
    'mingw-libvirt.spec.in',
  ]

  spec_conf = configuration_data()
  spec_conf.set('VERSION', meson.project_version())

  foreach file : spec_files
    configure_file(
      input: file,
      output: '@BASENAME@',
      configuration: spec_conf,
    )
  endforeach

  authors = run_command(python3_prog, meson_gen_authors_prog.path(), env: runutf8)
  authors_file = 'AUTHORS.rst.in'

  authors_conf = configuration_data()
  authors_conf.set('contributorslist', authors.stdout())

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
      meson_python_prog.path(), python3_prog.path(), meson_dist_prog.path(),
      meson.build_root(), file
    )
  endforeach
endif


# generate meson-config.h file
configure_file(output: 'meson-config.h', configuration: conf)


# generate run helper
run_conf = configuration_data()
run_conf.set('abs_builddir', meson.build_root())
configure_file(
  input: 'run.in',
  output: '@BASENAME@',
  configuration: run_conf,
)
run_command('chmod', 'a+x', meson.current_build_dir() / 'run')


# generate developer tooling files
tooling_files = [
  '.color_coded.in',
  '.ycm_extra_conf.py.in',
]

tooling_conf = configuration_data()
tooling_conf.set('abs_top_builddir', meson.build_root())
tooling_conf.set('abs_top_srcdir', meson.source_root())

foreach file : tooling_files
  configure_file(
    input: file,
    output: '@BASENAME@',
    configuration: tooling_conf,
  )
endforeach


# print configuration summary

driver_summary = {
  'QEMU': conf.has('WITH_QEMU'),
  'OpenVZ': conf.has('WITH_OPENVZ'),
  'VMware': conf.has('WITH_VMWARE'),
  'VBox': conf.has('WITH_VBOX'),
  'libxl': conf.has('WITH_LIBXL'),
  'LXC': conf.has('WITH_LXC'),
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
  'Sheepdog': conf.has('WITH_STORAGE_SHEEPDOG'),
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
  'libm': libm_dep.found(),
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
  'sanlock': conf.has('WITH_SANLOCK'),
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
  'Use -Werror': cc_flags.contains('-Werror'),
  'Warning Flags': supported_cc_flags,
  'docs': gen_docs,
  'tests': build_tests,
  'DTrace': conf.has('WITH_DTRACE_PROBES'),
  'firewalld': conf.has('WITH_FIREWALLD'),
  'firewalld-zone': conf.has('WITH_FIREWALLD_ZONE'),
  'nss': conf.has('WITH_NSS'),
  'numad': conf.has('WITH_NUMAD'),
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
