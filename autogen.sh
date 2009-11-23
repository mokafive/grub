#! /bin/sh

set -e

aclocal
autoconf
autoheader

echo timestamp > stamp-h.in

python util/import_gcry.py lib/libgcrypt/ .

for rmk in conf/*.rmk ${GRUB_CONTRIB}/*/conf/*.rmk; do
  if test -e $rmk ; then
    ruby genmk.rb < $rmk > `echo $rmk | sed 's/\.rmk$/.mk/'`
  fi
done
sh gendistlist.sh > DISTLIST

exit 0
