#!/usr/bin/env bash

sudo gdb /mnt/data/AMDSEV-DOCKER/AMDSEV/usr/local/bin/qemu-system-x86_64 << 'EOF'
directory /mnt/data/AMDSEV-DOCKER/AMDSEV/qemu/accel
set args -enable-kvm -cpu EPYC-v4 -machine q35 -smp 1,maxcpus=1 -m 2048M,slots=5,maxmem=10240M -no-reboot -drive if=pflash,format=raw,unit=0,file=/mnt/data/AMDSEV-DOCKER/AMDSEV/usr/local/share/qemu/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=/mnt/data/alexis/encrypted_vm_launch/new/AMDSEV/alexis-disk.fd -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true -machine memory-encryption=sev0,vmport=off -object memory-backend-memfd-private,id=ram1,size=2048M,share=true -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,discard=none -machine memory-backend=ram1,kvm-type=protected -kernel /boot/vmlinuz-6.6.0-snp-guest-690558b32fe6 -append "console=ttyS0 earlyprintk=serial root=/dev/sda2" -initrd /boot/initrd.img-6.6.0-snp-guest-690558b32fe6 -nographic -monitor pty -monitor unix:monitor,server,nowait 

break kvm-all.c:3257 if type == 0x40a0ae49
commands
silent
printf "s->vmfs: %d\n", s->vmfd
printf "kvm_userspace_memory_region2:\n"
print *((struct kvm_userspace_memory_region2*)arg)
continue
end

break sev.c:242
commands
silent
python
sev_cmd_id = gdb.selected_frame().read_var('input')['id']
print("input.id = ", end='')
if sev_cmd_id == 22:
    print("KVM_SEV_SNP_INIT")
    gdb.execute("print *((struct kvm_snp_init *) input.data)")
elif sev_cmd_id == 23:
    print("KVM_SEV_SNP_LAUNCH_START")
    gdb.execute("print *((struct kvm_sev_snp_launch_start *) input.data)")
elif sev_cmd_id == 24:
    print("KVM_SEV_SNP_LAUNCH_UPDATE")
    gdb.execute("print *((struct kvm_sev_snp_launch_update *) input.data)")
elif sev_cmd_id == 25:
    print("KVM_SEV_SNP_LAUNCH_FINISH")
    gdb.execute("print *((struct kvm_sev_snp_launch_finish *) input.data)")
else:
    print(f"{sev_cmd_id}")
end
continue
end

handle SIGUSR1 nostop noprint pass
run
EOF


# SEV COMMANDS executed by QEmu starting a SEV-SNP VM (ordered):
# 22 = KVM_SEV_SNP_INIT
# 23 = KVM_SEV_SNP_LAUNCH_START
# 24 = KVM_SEV_SNP_LAUNCH_UPDATE (6 times) 
# 25 = KVM_SEV_SNP_LAUNCH_FINISH
