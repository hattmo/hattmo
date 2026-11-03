run: build/initramfs.raw build/rootfs.raw vmlinuz-linux
	systemd-vmspawn --user --kvm=true --network-tap -x --image=./build/rootfs.raw --initrd=./build/initramfs.raw --linux=./vmlinuz-linux

build/initramfs.raw: mkinitcpio.conf
	mkdir -p build
	mkinitcpio -c ./mkinitcpio.conf -g ./build/initramfs.raw
	rm -rf build/initramfs
	mkdir build/initramfs
	cd build/initramfs && lsinitcpio -x ../initramfs.raw

build/rootfs.raw: mkosi.conf
	mkdir -p build
	mkosi -f build

clean:
	rm -rf build
	mkosi -ff clean
	rm -rf .cache
