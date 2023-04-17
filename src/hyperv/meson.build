hyperv_sources = [
  'hyperv_driver.c',
  'hyperv_network_driver.c',
  'hyperv_util.c',
  'hyperv_wmi.c',
  'hyperv_wmi_classes.c',
]

hyperv_gen_sources = custom_target(
  'virthypervgen',
  input: [
    'hyperv_wmi_generator.input',
  ],
  output: [
    'hyperv_wmi_classes.generated.c',
    'hyperv_wmi_classes.generated.h',
    'hyperv_wmi_classes.generated.typedef',
  ],
  command: [
    hyperv_wmi_generator_prog,
    meson.project_source_root() / 'src',
    meson.project_build_root() / 'src',
  ],
)

if conf.has('WITH_HYPERV')
  hyperv_lib = static_library(
    'virt_driver_hyperv',
    [
      hyperv_sources,
      hyperv_gen_sources[1],
    ],
    dependencies: [
      openwsman_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ]
  )

  libvirt_libs += hyperv_lib
endif
