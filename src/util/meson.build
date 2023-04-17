util_sources = [
  'glibcompat.c',
  'viracpi.c',
  'viralloc.c',
  'virarch.c',
  'virarptable.c',
  'viraudit.c',
  'virauth.c',
  'virauthconfig.c',
  'virbitmap.c',
  'virbpf.c',
  'virbuffer.c',
  'virccw.c',
  'vircgroup.c',
  'vircgroupbackend.c',
  'vircgroupv1.c',
  'vircgroupv2.c',
  'vircgroupv2devices.c',
  'vircommand.c',
  'virconf.c',
  'vircrypto.c',
  'virdaemon.c',
  'virdevmapper.c',
  'virdnsmasq.c',
  'virebtables.c',
  'virenum.c',
  'vireventglib.c',
  'vireventglibwatch.c',
  'vireventthread.c',
  'virfcp.c',
  'virfdstream.c',
  'virfile.c',
  'virfilecache.c',
  'virfirewall.c',
  'virfirewalld.c',
  'virfirmware.c',
  'virgdbus.c',
  'virgettext.c',
  'virgic.c',
  'virglibutil.c',
  'virhash.c',
  'virhashcode.c',
  'virhook.c',
  'virhostcpu.c',
  'virhostmem.c',
  'virhostuptime.c',
  'viridentity.c',
  'virinitctl.c',
  'viriptables.c',
  'viriscsi.c',
  'virjson.c',
  'virkeycode.c',
  'virkmod.c',
  'virlease.c',
  'virlockspace.c',
  'virlog.c',
  'virmacaddr.c',
  'virmacmap.c',
  'virmdev.c',
  'virmodule.c',
  'virnetdev.c',
  'virnetdevbandwidth.c',
  'virnetdevbridge.c',
  'virnetdevip.c',
  'virnetdevmacvlan.c',
  'virnetdevmidonet.c',
  'virnetdevopenvswitch.c',
  'virnetdevtap.c',
  'virnetdevveth.c',
  'virnetdevvlan.c',
  'virnetdevvportprofile.c',
  'virnetlink.c',
  'virnodesuspend.c',
  'virnuma.c',
  'virnvme.c',
  'virobject.c',
  'virpci.c',
  'virperf.c',
  'virpidfile.c',
  'virpolkit.c',
  'virportallocator.c',
  'virprocess.c',
  'virqemu.c',
  'virrandom.c',
  'virresctrl.c',
  'virrotatingfile.c',
  'virscsi.c',
  'virscsihost.c',
  'virscsivhost.c',
  'virseclabel.c',
  'virsecret.c',
  'virsecureerase.c',
  'virsocket.c',
  'virsocketaddr.c',
  'virstoragefile.c',
  'virstring.c',
  'virsysinfo.c',
  'virsystemd.c',
  'virthread.c',
  'virthreadjob.c',
  'virthreadpool.c',
  'virtime.c',
  'virtpm.c',
  'virtypedparam.c',
  'viruri.c',
  'virusb.c',
  'virutil.c',
  'viruuid.c',
  'virvhba.c',
  'virpcivpd.c',
  'virvsock.c',
  'virxml.c',
]

util_public_sources = files(
  'virerror.c',
  'virevent.c',
  'virtypedparam-public.c',
)

keycode_gen_sources = []

keycode_list = [
  'atset1',
  'atset2',
  'atset3',
  'linux',
  'osx',
  'qnum',
  'usb',
  'win32',
  'xtkbd',
]

keyname_list = [
  'linux',
  'osx',
  'win32',
]

keymap_gen_prog = find_program('keymap-gen')
keymap_src_file = keycodemapdb.get_variable('keymaps_csv')

foreach name : keycode_list
  keycode_gen_sources += custom_target(
    'virt_keycode_@0@'.format(name),
    input: keymap_src_file,
    output: 'virkeycodetable_@0@.h'.format(name),
    command: [
      keymap_gen_prog, 'code-table',
      '--lang', 'stdc',
      '--varname', 'virKeyCodeTable_@0@'.format(name),
      '@INPUT@', name,
    ],
    capture: true,
  )
endforeach

foreach name : keyname_list
  keycode_gen_sources += custom_target(
    'keyname_@0@'.format(name),
    input: keymap_src_file,
    output: 'virkeynametable_@0@.h'.format(name),
    command: [
      keymap_gen_prog, 'name-table',
      '--lang', 'stdc',
      '--varname', 'virKeyNameTable_@0@'.format(name),
      '@INPUT@', name,
    ],
    capture: true,
  )
endforeach

keycode_dep = declare_dependency(
  sources: keycode_gen_sources,
)

io_helper_sources = [
  'iohelper.c',
  'virfile.c',
]

virt_util_lib = static_library(
  'virt_util',
  [
    util_sources,
    util_public_sources,
    keycode_gen_sources,
    dtrace_gen_headers,
  ],
  dependencies: [
    acl_dep,
    audit_dep,
    capng_dep,
    devmapper_dep,
    gnutls_dep,
    intl_dep,
    libm_dep,
    libnl_dep,
    libutil_dep,
    numactl_dep,
    secdriver_dep,
    src_dep,
    thread_dep,
    win32_dep,
    yajl_dep,
  ],
)

libvirt_libs += virt_util_lib

if conf.has('WITH_LIBVIRTD')
  virt_helpers += {
    'name': 'libvirt_iohelper',
    'sources': [
      files(io_helper_sources),
      dtrace_gen_headers,
    ],
    'deps': [
      acl_dep,
      libutil_dep,
    ],
  }
endif

util_inc_dir = include_directories('.')
