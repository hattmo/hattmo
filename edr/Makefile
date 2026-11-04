run: mkosi.out/edr_test_os
	systemd-vmspawn --user --kvm=true --network-tap -x --image=./mkosi.output/edr_test_os --initrd=./mkosi.output/initrd --linux=./mkosi.output/edr_test_os.vmlinuz rdinit=/bin/edr

mkosi.out/edr_test_os: mkosi.conf
	cargo build
	mkosi -f build

clean:
	mkosi -ff clean
