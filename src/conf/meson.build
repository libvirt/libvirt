netdev_conf_sources = [
  'netdev_bandwidth_conf.c',
  'netdev_vlan_conf.c',
  'netdev_vport_profile_conf.c',
  'virnetworkportdef.c',
]

domain_conf_sources = [
  'backup_conf.c',
  'capabilities.c',
  'checkpoint_conf.c',
  'domain_addr.c',
  'domain_audit.c',
  'domain_capabilities.c',
  'domain_conf.c',
  'domain_nwfilter.c',
  'domain_postparse.c',
  'domain_validate.c',
  'moment_conf.c',
  'numa_conf.c',
  'snapshot_conf.c',
  'virdomaincheckpointobjlist.c',
  'virdomainjob.c',
  'virdomainmomentobjlist.c',
  'virdomainobjlist.c',
  'virdomainsnapshotobjlist.c',
  'virsavecookie.c',
]

event_conf_sources = [
  'domain_event.c',
  'network_event.c',
  'node_device_event.c',
  'object_event.c',
  'secret_event.c',
  'storage_event.c',
]

network_conf_sources = [
  'network_conf.c',
  'networkcommon_conf.c',
  'virnetworkobj.c',
]

nwfilter_conf_sources = [
  'nwfilter_conf.c',
  'nwfilter_ipaddrmap.c',
  'nwfilter_params.c',
  'virnwfilterbindingdef.c',
  'virnwfilterbindingobj.c',
  'virnwfilterbindingobjlist.c',
  'virnwfilterobj.c',
]

storage_conf_sources = [
  'storage_adapter_conf.c',
  'storage_capabilities.c',
  'storage_conf.c',
  'storage_encryption_conf.c',
  'storage_source_conf.c',
  'virstorageobj.c',
]

interface_conf_sources = [
  'interface_conf.c',
  'virinterfaceobj.c',
]

secret_conf_sources = [
  'secret_conf.c',
  'virsecretobj.c',
]

node_device_conf_sources = [
  'node_device_conf.c',
  'node_device_util.c',
  'virnodedeviceobj.c',
]

cpu_conf_sources = [
  'cpu_conf.c',
]

chrdev_conf_sources = [
  'virchrdev.c',
]

device_conf_sources = [
  'device_conf.c',
]

virt_conf_lib = static_library(
  'virt_conf',
  [
    chrdev_conf_sources,
    cpu_conf_sources,
    device_conf_sources,
    domain_conf_sources,
    event_conf_sources,
    interface_conf_sources,
    netdev_conf_sources,
    network_conf_sources,
    node_device_conf_sources,
    nwfilter_conf_sources,
    secret_conf_sources,
    storage_conf_sources,
  ],
  dependencies: [
    src_dep,
  ],
)

libvirt_libs += virt_conf_lib

conf_inc_dir = include_directories('.')

subdir('schemas')
