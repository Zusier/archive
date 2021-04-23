`
nano -w /etc/locale.gen`

Add these lines for english:

`en_US ISO-8859-1
en_US.UTF-8 UTF-8`

Next run `locale-gen` to generate alm the locale files.

Next list the available locales:

`eselect locale list`

Then select the one you want with:

`eselect locale set 3`

Now reload the environment:

`env-update && source /etc/profile && export PS1="(chroot) ${PS1}"`
