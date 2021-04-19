completion_commands = [
  'virsh',
  'virt-admin',
]

foreach command : completion_commands
  completion_conf = configuration_data()
  completion_conf.set('command', command)
  completion = configure_file(
    input: 'vsh.in',
    output: command,
    configuration: completion_conf,
  )
  install_data(completion, install_dir: bash_completion_dir)
endforeach
