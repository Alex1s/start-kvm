sudo /mnt/data/AMDSEV-DOCKER/AMDSEV/usr/local/bin/qemu-system-x86_64 -enable-kvm -cpu EPYC-v4 -machine q35 -smp 1,maxcpus=1 -m 2048M,slots=5,maxmem=10240M -no-reboot -drive if=pflash,format=raw,unit=0,file=/mnt/data/AMDSEV-DOCKER/AMDSEV/usr/local/share/qemu/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=/mnt/data/alexis/encrypted_vm_launch/new/AMDSEV/alexis-disk.fd -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true -machine memory-encryption=sev0,vmport=off -object memory-backend-memfd-private,id=ram1,size=2048M,share=true -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,discard=none -machine memory-backend=ram1,kvm-type=protected -kernel /boot/vmlinuz-6.6.0-snp-guest-690558b32fe6 -append "console=ttyS0 earlyprintk=serial root=/dev/sda2" -initrd /boot/initrd.img-6.6.0-snp-guest-690558b32fe6 -nographic -monitor pty -monitor unix:monitor,server,nowait --trace "kvm_sev*"