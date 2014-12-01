# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

# This Vagrantfile is only for FreeBSD testing; I do Linux development
# natively.
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = 'chef/freebsd-10.0'

  config.vm.synced_folder ".", "/vagrant", type: 'nfs', id: 'vagrant-root'

  config.vm.provision 'shell', inline: <<EOS
sudo pkg install -y gmake
EOS

  config.ssh.shell = '/bin/sh'
end
