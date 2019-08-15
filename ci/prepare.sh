# This script is used to prepare the environment that will be used
# to build libvirt inside the container.
#
# You can customize it to your liking, or alternatively use a
# completely different script by passing
#
#  CI_PREPARE_SCRIPT=/path/to/your/prepare/script
#
# to make.
#
# Note that this script will have root privileges inside the
# container, so it can be used for things like installing additional
# packages.
