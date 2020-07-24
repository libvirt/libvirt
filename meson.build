project(
    'libvirt', 'c',
    version: '6.7.0',
    license: 'LGPLv2+',
    meson_version: '>= 0.54.0',
    default_options: [
        'buildtype=debugoptimized',
        'b_pie=true',
        'c_std=gnu99',
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


# define top include directory

top_inc_dir = include_directories('.')


# generate meson-config.h file
configure_file(output: 'meson-config.h', configuration: conf)
