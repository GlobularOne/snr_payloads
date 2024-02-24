all: build archive

build: src/efi_disk_encryption_message.efi

src/uefi:
	git clone --no-checkout https://gitlab.com/bztsrc/posix-uefi.git src/posix-uefi
	git -C src/posix-uefi sparse-checkout set --no-cone '/uefi/*'
	git -C src/posix-uefi checkout
	cp -r src/posix-uefi/uefi src/uefi
	rm -rf src/posix-uefi

src/efi_disk_encryption_message.efi: src/uefi
	$(MAKE) -C src -f efi_disk_encryption_message.mk

archive:
	cp -r snr_payloads payload_set
	mkdir -p payload_set/data
	cp src/efi_disk_encryption_message.efi payload_set/data
	tar -C payload_set -czf payload_set.tar.gz .

clean:
	$(MAKE) -C src -f efi_disk_encryption_message.mk clean
	rm -rf payload_set src/posix-uefi src/uefi
