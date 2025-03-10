cp -r ../lab2/ ../dist/rootfs/usr/
cd ../dist/rootfs/
find . | cpio -o -H newc | bzip2 > ../rootfs.cpio.bz2
cd ../../lab2/