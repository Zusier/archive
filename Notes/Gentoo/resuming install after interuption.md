Perhaps you left your laptop compiling your kernel during install and the cord miraculously unplugged and the battery ran out.
Oh fuck you gotta do everything again. Fear not! Simply re-mount your disks again:

`
swapon /dev/sda2
mount /dev/sda3 /mnt/gentoo
mkdir /mnt/gentoo/boot
mount /dev/sda1 /mnt/gentoo/boot
`
Then chroot:

`
mount --types proc /proc /mnt/gentoo/proc
mount --rbind /sys /mnt/gentoo/sys
mount --make-rslave /mnt/gentoo/sys
mount --rbind /dev /mnt/gentoo/dev
mount --make-rslave /mnt/gentoo/dev
chroot /mnt/gentoo /bin/bash
env-update
source /etc/profile
`

Finally resume where you left off, I recommend doing the last step you did again.
