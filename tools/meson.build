tools_inc_dir = include_directories('.')

tools_dep = declare_dependency(
  compile_args: coverage_flags,
  dependencies: [
    libxml_dep,
    glib_dep,
  ],
  include_directories: [
    libvirt_inc,
    src_inc_dir,
    util_inc_dir,
    top_inc_dir,
  ],
  link_args: (
    libvirt_relro
    + libvirt_no_indirect
    + libvirt_no_undefined
  ),
)
