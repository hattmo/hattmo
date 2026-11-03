run: mkosi.out/edr_test_os
	systemd-vmspawn --user --kvm=true --network-tap -x --image=./build/rootfs.raw --initrd=./build/initramfs.raw --linux=./vmlinuz-linux

mkosi.out/edr_test_os: mkosi.conf
	mkosi -f mkosi.out

clean:
	rm -rf mkosi.out/*
	mkosi -ff clean
