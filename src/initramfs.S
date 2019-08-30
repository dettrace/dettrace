.section .rodata.initramfs

.global __initramfs_start
__initramfs_start:
	.incbin __INITRAMFS__

.global __initramfs_end
__initramfs_end:

.global __initramfs_size
__initramfs_size:
	.align 0x8
	.long __initramfs_end - __initramfs_start
