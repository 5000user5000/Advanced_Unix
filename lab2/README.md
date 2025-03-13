# Cryptomod: Kernel Module for AES Encryption/Decryption

This project implements a Linux kernel module (`cryptomod`) that provides AES encryption and decryption functionality using the `ECB` mode. The module interacts with user-space applications via the `/dev/cryptodev` character device and exposes statistics via `/proc/cryptomod`.

## Features
- Supports AES encryption and decryption in **ECB mode**.
- Configurable via `ioctl` interface.
- Two I/O modes:
  - `BASIC`: Buffers all input and processes it upon finalization.
  - `ADV`: Processes data incrementally, block by block.
- Provides a `/proc/cryptomod` interface to monitor encryption statistics.

## File Structure
```
.
├── cryptomod.c       # Kernel module source code
├── cryptomod.h       # Header file with ioctl definitions
├── Makefile          # Compilation rules
├── copy.sh           # Script to copy and package files for deployment
├── lab2.md           # Lab instructions and details
```

## Installation & Usage

### 1. Build the Kernel Module
Ensure you have a proper Linux kernel build environment set up. Then, run:
```sh
make
```
This generates the `cryptomod.ko` module file.

### 2. Load the Module
Use `insmod` to insert the module into the kernel:
```sh
sudo insmod cryptomod.ko
```
Verify that the module is loaded:
```sh
lsmod | grep cryptomod
```

### 3. Device and Proc File Verification
Once the module is loaded, ensure the following files are created:
- `/dev/cryptodev`: Character device for encryption/decryption.
- `/proc/cryptomod`: Provides statistics on encryption activity.

To check:
```sh
ls -l /dev/cryptodev
cat /proc/cryptomod
```

### 4. Testing
A test program (`test_crypto`) is available for validating the module. You can run different test cases:
```sh
./test_crypto test 0  # Runs test case 0 <totally test case 0~6 >
```
You can also manually encrypt and decrypt files:
```sh
./test_crypto enc -i input.txt -o encrypted.bin -k "e381aae38293e381a7e698a5e697a5e5bdb1e38284e381a3e3819fe381ae213f" -s 128 -m ADV
```

### 5. Unloading the Module
To remove the module:
```sh
sudo rmmod cryptomod
```
Ensure the module is unloaded:
```sh
lsmod | grep cryptomod
```

## Packaging for Deployment
If deploying within a QEMU-based environment, use the provided `copy.sh` script:
```sh
sh copy.sh
```
This copies necessary files to the deployment directory and updates the root filesystem archive.

## Additional Information
For further details, refer to `lab2.md`, which contains the full lab instructions and evaluation criteria.

