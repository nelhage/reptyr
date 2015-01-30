# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

# This Vagrantfile is only for FreeBSD testing; I do Linux development
# natively.
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "freebsd" do |machine|
    machine.vm.box = 'chef/freebsd-10.0'
    machine.vm.provision 'shell', inline: <<EOS
sudo pkg install -y gmake
EOS

    machine.ssh.shell = '/bin/sh'
  end

  config.vm.define 'fedora-20-x86' do |machine|
    machine.vm.box = 'chef/fedora-20-i386'
  end

  config.vm.define 'fedora-20-x86_64' do |machine|
    machine.vm.box = 'chef/fedora-20'
  end

  config.vm.synced_folder ".", "/vagrant", type: 'nfs', id: 'vagrant-root'

end
