#!/bin/sh

TESTS="test01 test02 test03 test04a test04b test05 test06a test06b test07a test07b"

make $TESTS

for t in $TESTS; do
	echo "===== TEST $t ====="
	./$t
done
