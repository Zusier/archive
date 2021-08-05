# Funtoo Install

Funtoo installation, for personal use.

## Download Gentoo MinimalInstall CD

[Download Link](https://www.gentoo.org/downloads)

You know the deal, download and put on ventoy usb.

## Partitioning

### GPT+UEFI

Take note of the current partition scheme:
```
$ lsblk
```

Open gdisk:

```
$ gdisk /dev/nvme0n1

# Wipe the disk
$ o
# type Y

# boot sector
$ o
$ 1
$ >>
$ +128M
$ EF00

# Swap
$ o
$ 2
$ >>
$ +16G
$ 8200

# root
$ o
$ 3
$ >> 
$ +128G
$ >>
```

You can rename partitions using `c` in `gdisk`

Finish off the partition setup by using `w` in `gdisk`

## Filesystems

Let's create the boot partition filesystem:

```
mkfs.vfat -F 32 /dev/nvme0n1p1
```

To initialize your swap disk, run the following:

```
mkswap /dev/nvme0n1p2
swapon /dev/nvme0n1p2
```

To format the root partition as Ext4:

```
mkfs.ext4 /dev/nvme0n1p3
```
## Mounting The filesystems

```
mkdir /mnt/funtoo
mount /dev/nvme0n1p3 /mnt/funtoo
mkdir /mnt/funtoo/boot
mount /dev/nvme0n1p1 /mnt/funtoo/boot
```

https://www.funtoo.org/Install/Setting_the_Date
