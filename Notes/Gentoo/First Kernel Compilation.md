Make sure you compiled the [gentoo sources](https://packages.gentoo.org/packages/sys-kernel/gentoo-sources) before doing so.

First list the available kernels, you may only see one.

`eselect kernel list`

Then set the kernel you want.

`eselect kernel set 1`

CD into the kernel directory:

`cd /usr/src/linux`
Then run make menuconfig
`make menuconfig`

From here you will see different symbols, heres what they mean

`| [*], [ ] | These options can either be deactivated or activated, simple. |
| < >, <*>, <M> | These options can be activated, deactivated or activated as a module. [What's the difference?](https://wiki.gentoo.org/wiki/Kernel_Modules) |
| {*}, {M} | These can be activated or as a module but not deactivated because there it is a dependency of something else. |
| -*-, -M- | You have no option, you will definitely see these as the required gentoo [options]()|
`

**TIP:** You can search the options with the `/` key.

It may be helpful to read [this](https://wiki.gentoo.org/wiki/Kernel/Gentoo_Kernel_Configuration_Guide)
