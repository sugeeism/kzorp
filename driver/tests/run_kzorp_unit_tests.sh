#!/bin/bash

## Dependencies
# sudo modprobe kvm
# sudo service virtualbox stop
# sudo service qemu-kvm start
# sudo apt-get install kvm cloud-utils genisoimage

function print_help(){
    echo -e \
"Usage of $0:\n" \
"   $0 [options]\n" \
"Options:\n" \
"   -r | --release RELEASE - Release name of the package to be installed\n" \
"   -o | --os OS - OS name of the package to be installed\n" \
"   -a | --arch ARCHITECTURE - Architecture name of the package to be installed\n" \
"   -u | --apt-url URL - URL of the deb package source\n"
"   -p | --path PATH - Path of the tests directory\n"
"   -h | --help - Display this information \n"
}

Root="/tmp/kzorp_test_run"

TestSeedConf="run_test.conf"

Architecture="amd64"

OSName="ubuntu"
OSVersion="14.04"

KernelHeaderPackageNameDeb="linux-headers-generic"
ZorpPackageNamesDeb="kzorp-dkms python-kzorp python-zorp-base"
TestPackageNamesDeb="python-junitxml python-nose"

OSPackageSourcesDeb="deb http://mirror.balabit/ubuntu/ trusty main"
OSPackageSourcesDeb="deb http://hu.archive.ubuntu.com/ubuntu/ trusty main"

PackageInstallCommandDeb="DEBIAN_FRONTEND=noninteractive apt-get install -y --force-yes"

APTSourceURL="http://hapci.balabit/zbs2"
OS="ubuntu-trusty"
ReleaseName="zorp-6.0dbg"

while (( $# )); do
  case $1 in
    "-r" | "--release") ReleaseName="$2"; shift 2;;
    "-o" | "--os") OS="$2"; shift 2;;
    "-a" | "--arch") Architecture="$2"; shift 2;;
    "-u" | "--apt-url") APTSourceURL="$2"; shift 2;;
    "-p" | "--path") Root="$2"; shift 2;;
    "-h" | "--help") print_help; exit 0;;
    *) echo "Invalid option $1" >&2; print_help; exit 1;;
  esac
done

case ${Architecture} in
  "amd64") Qemu="qemu-system-x86_64 --enable-kvm";;
  "i386") Qemu="qemu-system-i386 --enable-kvm";;
  "arm64") Qemu="qemu-system-arm -machine virt";;
  *) echo "Error: ${Architecture} is not a supported architecture. Only amd64, i386 and arm64 are supported."; exit 1;;
esac

TestRoot="${Root}/tests"
OSImageDir="${Root}/disk_images"
OSImageName="disk.img.dist_${OSName}_${OSVersion}_${Architecture}"
OSImagePath="${OSImageDir}/${OSImageName}"
OSImagePathOrig="${OSImageDir}/${OSImageName}.orig"
OSImagePathQemu="${OSImageDir}/${OSImageName}.qemu"
OSImagePathSeed="${OSImageDir}/${OSImageName}.seed"

ImageURL="http://cloud-images.ubuntu.com/server/releases/${OSVersion}/release"
ImageURL="${ImageURL}/ubuntu-${OSVersion}-server-cloudimg-${Architecture}-disk1.img"

set -ex
ZorpPackageSourceDeb="deb [arch=$Architecture] $APTSourceURL $OS/$ReleaseName main zorp"

if [ ! -d ${OSImageDir} ]; then
  mkdir -p ${OSImageDir}
fi

## download the image (only once)
if [ ! -f ${OSImagePath} ]; then
  echo "Image not found under ${OSImagePath}"
  wget $ImageURL -O ${OSImagePath}
fi

## Create a file with some user-data in it
mkdir -p $TestRoot
touch $TestRoot/kzorp_test_result_communication.xml

cat > $TestSeedConf <<EOF
#cloud-config
userid: zorp
password: zorp
chpasswd: { expire: False }
ssh_pwauth: True
apt_sources:
 - source: '${ZorpPackageSourceDeb}'
   filename: zorp.list
 - source: '${OSPackageSourcesDeb}'
   filename: os.list
package_upgrade: true
system_info:
 apt_get_command: ['apt-get', '-y', '--force-yes']
 apt_get_upgrade_subcommand: install
packages:
 - python-kzorp
 - kzorp-dkms
runcmd:
 - mkdir -p $TestRoot
 - sudo mount -t 9p -o trans=virtio,version=9p2000.L hostshare $TestRoot
 - sudo $PackageInstallCommandDeb ${KernelHeaderPackageNameDeb} ${ZorpPackageNamesDeb} ${TestPackageNamesDeb}
 - sudo modprobe kzorp
 - sudo nosetests --with-xunit ${TestRoot}/communication/testall.py --xunit-file=$TestRoot/kzorp_test_result_communication.xml
 - sudo cp /var/log/kern.log ${TestRoot}
 - sudo cat /var/log/kern.log
 - sudo poweroff
EOF


if [ ! -f ${OSImagePathOrig} ]; then
  ## Convert the compressed qcow file downloaded to a uncompressed qcow2
  qemu-img convert -O qcow2 ${OSImagePath} ${OSImagePathOrig}
fi

## create the disk with NoCloud data on it.
cloud-localds ${OSImagePathSeed} $TestSeedConf

## Create a delta disk to keep our .orig file pristine
qemu-img create -f qcow2 -b ${OSImagePathOrig} ${OSImagePathQemu}

## Boot a kvm
#In a terminal you can login to the machine through the curses interface
#qemu-system-x86_64 --enable-kvm -curses -net nic -net user -hda ${OSImagePathQemu} -hdb ${OSImagePathSeed} -m 2048 -fsdev local,security_model=passthrough,id=fsdev0,path=$TestRoot -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare
#Jenkins runs this without terminal
${Qemu} -nographic -net nic -net user -hda ${OSImagePathQemu} -hdb ${OSImagePathSeed} -m 2048 -fsdev local,security_model=passthrough,id=fsdev0,path=$TestRoot -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare
