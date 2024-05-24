all: build archive

build: src/efi_disk_encryption_message.efi src/bios_disk_encryption_message.bin

src/uefi:
	git clone --no-checkout https://gitlab.com/bztsrc/posix-uefi.git src/posix-uefi
	git -C src/posix-uefi sparse-checkout set --no-cone '/uefi/*'
	git -C src/posix-uefi checkout
	cp -r src/posix-uefi/uefi src/uefi
	rm -rf src/posix-uefi

src/efi_disk_encryption_message.efi: src/uefi
	$(MAKE) -C src -f efi_disk_encryption_message.mk

src/bios_disk_encryption_message.bin:
	$(MAKE) -C src -f bios_disk_encryption_message.mk

archive:
	cp -r snr_payloads payload_set
	mkdir -p payload_set/data
	cp src/efi_disk_encryption_message.efi payload_set/data/EFIBOOTX64.EFI
	cp src/bios_disk_encryption_message.bin payload_set/data/bios_disk_encryption_message.bin
	tar -C payload_set -czf payload_set.tar.gz .

clean:
	$(MAKE) -C src -f efi_disk_encryption_message.mk clean
	$(MAKE) -C src -f bios_disk_encryption_message.mk clean
	rm -rf payload_set src/posix-uefi src/uefi
