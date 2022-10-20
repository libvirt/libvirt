# we need to replace proper paths to our schemas in the test schemas
virschematest_test_schemas_conf = configuration_data({
  'SCHEMADIR': meson.project_source_root() / 'src' / 'conf' / 'schemas',
})

virschematest_schemas = [
  'cpu-baseline.rng.in',
  'device.rng.in',
  'privatedata.rng.in',
]

foreach file : virschematest_schemas
  configure_file(
    input: file,
    output: '@BASENAME@',
    configuration: virschematest_test_schemas_conf,
  )
endforeach
