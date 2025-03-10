/*
 * cryptomod.c - Kernel module for AES encryption/decryption via /dev/cryptodev
 *
 * 本範例利用 skcipher API 實作 AES ECB 模式加解密，
 * 並透過 ioctl 與 /proc/cryptomod 介面與使用者互動。
 *
 * 注意：本程式的 ioctl 命令與結構定義均與 cryptomod.h 保持一致，
 *       包含魔數、命令編號以及 struct CryptoSetup 成員順序。
 */

 #include <linux/module.h>
 #include <linux/init.h>
 #include <linux/fs.h>
 #include <linux/cdev.h>
 #include <linux/uaccess.h>
 #include <linux/slab.h>
 #include <linux/mutex.h>
 #include <linux/proc_fs.h>
 #include <linux/crypto.h>
 #include <crypto/skcipher.h>
 #include <linux/ioctl.h>
 #include <linux/string.h>
 #include <linux/scatterlist.h>
 
 #include "cryptomod.h"
 
 #define DEVICE_NAME "cryptodev"
 #define CLASS_NAME  "crypto"
 /* 緩衝區大小可根據需求調整 */
 #define MAX_BUF_SIZE 4096
 
 /* 全域統計資料 */
 static int total_bytes_read = 0;
 static int total_bytes_written = 0;
 static int byte_freq[256] = {0};
 static DEFINE_MUTEX(counter_lock);
 
 /* 每個 open 的私有資料 */
 struct cryptodev_priv {
     enum CryptoMode c_mode;    // ENC 或 DEC
     enum IOMode io_mode;       // BASIC 或 ADV
     int key_len;
     char key[CM_KEY_MAX_LEN];
     struct crypto_skcipher *tfm;      // AES transform handle
     struct skcipher_request *req;     // 加解密請求
     unsigned char *in_buf;            // 輸入暫存區
     unsigned char *out_buf;           // 輸出暫存區
     size_t in_size;                   // in_buf 資料長度
     size_t out_size;                  // out_buf 中可讀取資料長度
     bool finalized;
 };
 
 /* --------------------- File Operations --------------------- */
 
 static int cryptodev_open(struct inode *inode, struct file *filp)
 {
     struct cryptodev_priv *priv;
 
     priv = kzalloc(sizeof(*priv), GFP_KERNEL);
     if (!priv)
         return -ENOMEM;
 
     priv->in_buf = kmalloc(MAX_BUF_SIZE, GFP_KERNEL);
     priv->out_buf = kmalloc(MAX_BUF_SIZE, GFP_KERNEL);
     if (!priv->in_buf || !priv->out_buf) {
         kfree(priv->in_buf);
         kfree(priv->out_buf);
         kfree(priv);
         return -ENOMEM;
     }
     priv->in_size = 0;
     priv->out_size = 0;
     priv->finalized = false;
     priv->tfm = NULL;
     priv->req = NULL;
     filp->private_data = priv;
     return 0;
 }
 
 static int cryptodev_release(struct inode *inode, struct file *filp)
 {
     struct cryptodev_priv *priv = filp->private_data;
     if (priv->tfm)
         crypto_free_skcipher(priv->tfm);
     if (priv->req)
         skcipher_request_free(priv->req);
     kfree(priv->in_buf);
     kfree(priv->out_buf);
     kfree(priv);
     return 0;
 }
 
 static long cryptodev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
 {
     struct cryptodev_priv *priv = filp->private_data;
     int ret, i;
     size_t blocks;
     struct CryptoSetup user_setup;
 
     switch (cmd) {
     case CM_IOC_SETUP:
         /* 修改這裡：返回 -EINVAL 而非 -EBUSY */
         if (copy_from_user(&user_setup, (void __user *)arg, sizeof(user_setup)))
             return -EINVAL;
         /* 驗證 key 長度是否正確 */
         if (!(user_setup.key_len == 16 || user_setup.key_len == 24 || user_setup.key_len == 32))
             return -EINVAL;
         /* 驗證 io_mode 與 c_mode 是否為合法值 */
         if (user_setup.io_mode != BASIC && user_setup.io_mode != ADV)
             return -EINVAL;
         if (user_setup.c_mode != ENC && user_setup.c_mode != DEC)
             return -EINVAL;
         /* 將設定參數複製到私有資料 */
         memcpy(priv->key, user_setup.key, user_setup.key_len);
         priv->key_len = user_setup.key_len;
         priv->io_mode = user_setup.io_mode;
         priv->c_mode = user_setup.c_mode;
         /* 清除先前緩衝與狀態 */
         priv->in_size = 0;
         priv->out_size = 0;
         priv->finalized = false;
         if (priv->tfm)
             crypto_free_skcipher(priv->tfm);
         if (priv->req)
             skcipher_request_free(priv->req);
         priv->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
         if (IS_ERR(priv->tfm))
             return PTR_ERR(priv->tfm);
         ret = crypto_skcipher_setkey(priv->tfm, priv->key, priv->key_len);
         if (ret) {
             crypto_free_skcipher(priv->tfm);
             priv->tfm = NULL;
             return -EINVAL;
         }
         priv->req = skcipher_request_alloc(priv->tfm, GFP_KERNEL);
         if (!priv->req) {
             crypto_free_skcipher(priv->tfm);
             priv->tfm = NULL;
             return -ENOMEM;
         }
         break;
 
     case CM_IOC_FINALIZE:
         if (!priv->tfm)
             return -EINVAL;
         if (priv->finalized)
             return -EINVAL;
         if (priv->io_mode == BASIC) {
             if (priv->c_mode == ENC) {
                 size_t pad;
                 if (priv->in_size % CM_BLOCK_SIZE == 0)
                     pad = CM_BLOCK_SIZE;
                 else
                     pad = CM_BLOCK_SIZE - (priv->in_size % CM_BLOCK_SIZE);
                 if (priv->in_size + pad > MAX_BUF_SIZE)
                     return -EINVAL;
                 memset(priv->in_buf + priv->in_size, pad, pad);
                 priv->in_size += pad;
                 blocks = priv->in_size / CM_BLOCK_SIZE;
                 for (i = 0; i < blocks; i++) {
                     struct scatterlist sg_in, sg_out;
                     sg_init_one(&sg_in, priv->in_buf + i * CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                     sg_init_one(&sg_out, priv->out_buf + i * CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                     skcipher_request_set_crypt(priv->req, &sg_in, &sg_out, CM_BLOCK_SIZE, NULL);
                     ret = crypto_skcipher_encrypt(priv->req);
                     if (ret)
                         return ret;
                 }
                 priv->out_size = priv->in_size;
             } else if (priv->c_mode == DEC) {
                 if (priv->in_size % CM_BLOCK_SIZE != 0)
                     return -EINVAL;
                 blocks = priv->in_size / CM_BLOCK_SIZE;
                 for (i = 0; i < blocks; i++) {
                     struct scatterlist sg_in, sg_out;
                     sg_init_one(&sg_in, priv->in_buf + i * CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                     sg_init_one(&sg_out, priv->out_buf + i * CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                     skcipher_request_set_crypt(priv->req, &sg_in, &sg_out, CM_BLOCK_SIZE, NULL);
                     ret = crypto_skcipher_decrypt(priv->req);
                     if (ret)
                         return ret;
                 }
                 {
                     unsigned char pad = priv->out_buf[priv->in_size - 1];
                     for (i = 0; i < pad; i++) {
                         if (priv->out_buf[priv->in_size - 1 - i] != pad)
                             return -EINVAL;
                     }
                     priv->out_size = priv->in_size - pad;
                 }
             }
         } else if (priv->io_mode == ADV) {
             if (priv->c_mode == ENC) {
                 if (priv->in_size > 0) {
                     size_t pad;
                     if (priv->in_size % CM_BLOCK_SIZE == 0)
                         pad = CM_BLOCK_SIZE;
                     else
                         pad = CM_BLOCK_SIZE - (priv->in_size % CM_BLOCK_SIZE);
                     if (priv->in_size + pad > MAX_BUF_SIZE)
                         return -EINVAL;
                     memset(priv->in_buf + priv->in_size, pad, pad);
                     priv->in_size += pad;
                     blocks = priv->in_size / CM_BLOCK_SIZE;
                     for (i = 0; i < blocks; i++) {
                         struct scatterlist sg_in, sg_out;
                         sg_init_one(&sg_in, priv->in_buf + i * CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                         sg_init_one(&sg_out, priv->out_buf + priv->out_size, CM_BLOCK_SIZE);
                         skcipher_request_set_crypt(priv->req, &sg_in, &sg_out, CM_BLOCK_SIZE, NULL);
                         ret = crypto_skcipher_encrypt(priv->req);
                         if (ret)
                             return ret;
                         priv->out_size += CM_BLOCK_SIZE;
                     }
                     priv->in_size = 0;
                 }
             } else if (priv->c_mode == DEC) {
                 if (priv->in_size != CM_BLOCK_SIZE)
                     return -EINVAL;
                 {
                     struct scatterlist sg_in, sg_out;
                     sg_init_one(&sg_in, priv->in_buf, CM_BLOCK_SIZE);
                     sg_init_one(&sg_out, priv->out_buf + priv->out_size, CM_BLOCK_SIZE);
                     skcipher_request_set_crypt(priv->req, &sg_in, &sg_out, CM_BLOCK_SIZE, NULL);
                     ret = crypto_skcipher_decrypt(priv->req);
                     if (ret)
                         return ret;
                     priv->out_size += CM_BLOCK_SIZE;
                     priv->in_size = 0;
                 }
                 if (priv->out_size > 0) {
                     unsigned char pad = priv->out_buf[priv->out_size - 1];
                     for (i = 0; i < pad; i++) {
                         if (priv->out_buf[priv->out_size - 1 - i] != pad)
                             return -EINVAL;
                     }
                     priv->out_size -= pad;
                 }
             }
         }
         priv->finalized = true;
         break;
 
     case CM_IOC_CLEANUP:
         if (!priv->tfm)
             return -EINVAL;
         priv->in_size = 0;
         priv->out_size = 0;
         priv->finalized = false;
         break;
 
     case CM_IOC_CNT_RST:
         mutex_lock(&counter_lock);
         total_bytes_read = 0;
         total_bytes_written = 0;
         memset(byte_freq, 0, sizeof(byte_freq));
         mutex_unlock(&counter_lock);
         break;
 
     default:
         return -EINVAL;
     }
 
     return 0;
 }
 
 static ssize_t cryptodev_write(struct file *filp, const char __user *buf,
                                 size_t count, loff_t *ppos)
 {
     struct cryptodev_priv *priv = filp->private_data;
     ssize_t processed;
     size_t space;
     int ret = 0;
 
     /* 檢查設備是否已設置 */
     if (!priv->tfm)
         return -EINVAL;
     if (priv->finalized)
         return -EINVAL;
 
     space = MAX_BUF_SIZE - priv->in_size;
     if (count > space)
         count = space;
     if (copy_from_user(priv->in_buf + priv->in_size, buf, count))
         return -EBUSY;
     priv->in_size += count;
     processed = count;
 
     mutex_lock(&counter_lock);
     total_bytes_written += count;
     mutex_unlock(&counter_lock);
 
     if (priv->io_mode == ADV && priv->tfm) {
         if (priv->c_mode == ENC) {
             while (priv->in_size > CM_BLOCK_SIZE) {
                 struct scatterlist sg_in, sg_out;
                 sg_init_one(&sg_in, priv->in_buf, CM_BLOCK_SIZE);
                 sg_init_one(&sg_out, priv->out_buf + priv->out_size, CM_BLOCK_SIZE);
                 skcipher_request_set_crypt(priv->req, &sg_in, &sg_out, CM_BLOCK_SIZE, NULL);
                 ret = crypto_skcipher_encrypt(priv->req);
                 if (ret)
                     return ret;
                 priv->out_size += CM_BLOCK_SIZE;
                 memmove(priv->in_buf, priv->in_buf + CM_BLOCK_SIZE, priv->in_size - CM_BLOCK_SIZE);
                 priv->in_size -= CM_BLOCK_SIZE;
             }
         } else if (priv->c_mode == DEC) {
             while (priv->in_size >= 2 * CM_BLOCK_SIZE) {
                 struct scatterlist sg_in, sg_out;
                 sg_init_one(&sg_in, priv->in_buf, CM_BLOCK_SIZE);
                 sg_init_one(&sg_out, priv->out_buf + priv->out_size, CM_BLOCK_SIZE);
                 skcipher_request_set_crypt(priv->req, &sg_in, &sg_out, CM_BLOCK_SIZE, NULL);
                 ret = crypto_skcipher_decrypt(priv->req);
                 if (ret)
                     return ret;
                 priv->out_size += CM_BLOCK_SIZE;
                 memmove(priv->in_buf, priv->in_buf + CM_BLOCK_SIZE, priv->in_size - CM_BLOCK_SIZE);
                 priv->in_size -= CM_BLOCK_SIZE;
             }
         }
     }
 
     return processed;
 }
 
 static ssize_t cryptodev_read(struct file *filp, char __user *buf,
                                size_t count, loff_t *ppos)
 {
     struct cryptodev_priv *priv = filp->private_data;
     ssize_t ret;
     size_t to_copy, j;
 
     /* 若設備尚未設置，返回 -EINVAL */
     if (!priv->tfm)
         return -EINVAL;
     if (priv->out_size == 0) {
         if (!priv->finalized)
             return -EAGAIN;
         else
             return 0;
     }
     to_copy = (count > priv->out_size) ? priv->out_size : count;
 
     mutex_lock(&counter_lock);
     total_bytes_read += to_copy;
     if (priv->c_mode == ENC) {
         for (j = 0; j < to_copy; j++) {
             byte_freq[ priv->out_buf[j] ]++;
         }
     }
     mutex_unlock(&counter_lock);
 
     if (copy_to_user(buf, priv->out_buf, to_copy))
         return -EBUSY;
     memmove(priv->out_buf, priv->out_buf + to_copy, priv->out_size - to_copy);
     priv->out_size -= to_copy;
     ret = to_copy;
     return ret;
 }
 
 static const struct file_operations cryptodev_fops = {
     .owner = THIS_MODULE,
     .open = cryptodev_open,
     .release = cryptodev_release,
     .unlocked_ioctl = cryptodev_ioctl,
     .write = cryptodev_write,
     .read = cryptodev_read,
 };
 
 /* --------------------- /proc/cryptomod Interface --------------------- */
 
 static ssize_t cryptomod_proc_read(struct file *file, char __user *buf,
                                    size_t count, loff_t *ppos)
 {
     char *buffer;
     int len = 0;
     int i, j;
     ssize_t ret;
 
     buffer = kmalloc(4096, GFP_KERNEL);
     if (!buffer)
         return -ENOMEM;
 
     mutex_lock(&counter_lock);
     len += scnprintf(buffer + len, 4096 - len, "%d %d\n",
                      total_bytes_read, total_bytes_written);
     for (i = 0; i < 16; i++) {
         for (j = 0; j < 16; j++) {
             len += scnprintf(buffer + len, 4096 - len, "%d ", byte_freq[i * 16 + j]);
         }
         len += scnprintf(buffer + len, 4096 - len, "\n");
     }
     mutex_unlock(&counter_lock);
 
     ret = simple_read_from_buffer(buf, count, ppos, buffer, len);
     kfree(buffer);
     return ret;
 }
 
 static const struct proc_ops cryptomod_proc_ops = {
     .proc_read = cryptomod_proc_read,
 };
 
 static dev_t dev_number;
 static struct cdev cryptodev_cdev;
 static struct class *cryptodev_class = NULL;
 static struct proc_dir_entry *proc_entry = NULL;
 
 static int __init cryptodev_init(void)
 {
     int ret;
 
     ret = alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
     if (ret < 0) {
         printk(KERN_ERR "cryptomod: Failed to allocate chrdev region\n");
         return ret;
     }
     cdev_init(&cryptodev_cdev, &cryptodev_fops);
     ret = cdev_add(&cryptodev_cdev, dev_number, 1);
     if (ret < 0) {
         unregister_chrdev_region(dev_number, 1);
         printk(KERN_ERR "cryptomod: Failed to add cdev\n");
         return ret;
     }
     cryptodev_class = class_create(CLASS_NAME);
     if (IS_ERR(cryptodev_class)) {
         cdev_del(&cryptodev_cdev);
         unregister_chrdev_region(dev_number, 1);
         printk(KERN_ERR "cryptomod: Failed to create class\n");
         return PTR_ERR(cryptodev_class);
     }
     device_create(cryptodev_class, NULL, dev_number, NULL, DEVICE_NAME);
 
     proc_entry = proc_create("cryptomod", 0444, NULL, &cryptomod_proc_ops);
     if (!proc_entry) {
         device_destroy(cryptodev_class, dev_number);
         class_destroy(cryptodev_class);
         cdev_del(&cryptodev_cdev);
         unregister_chrdev_region(dev_number, 1);
         printk(KERN_ERR "cryptomod: Failed to create /proc entry\n");
         return -ENOMEM;
     }
     printk(KERN_INFO "cryptomod: Module loaded successfully\n");
     return 0;
 }
 
 static void __exit cryptodev_exit(void)
 {
     proc_remove(proc_entry);
     device_destroy(cryptodev_class, dev_number);
     class_destroy(cryptodev_class);
     cdev_del(&cryptodev_cdev);
     unregister_chrdev_region(dev_number, 1);
     printk(KERN_INFO "cryptomod: Module unloaded\n");
 }
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Your Name");
 MODULE_DESCRIPTION("Cryptomod: Kernel Module for AES Encryption/Decryption");
 
 module_init(cryptodev_init);
 module_exit(cryptodev_exit);
 