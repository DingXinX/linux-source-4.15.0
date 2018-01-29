#include <linux/module.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/err.h>

#define ADDR_SIZE			256*1024
#define SHA256_DIGEST_SIZE	32

static int sha256_test(char *plaintext, u8 psize, u8 *output)
{
	struct crypto_shash *tfm;
	struct shash_desc *shash;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		BT_DBG("crypto_alloc_ahash failed: err %ld", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}


	shash = kzalloc(sizeof(*shash) + crypto_shash_descsize(tfm),
			GFP_KERNEL);
	if (!shash) {
		ret = -ENOMEM;
		goto failed;
	}

	shash->tfm = tfm;
	shash->flags = 0;

	ret = crypto_shash_digest(shash, plaintext, psize, output);

	kfree(shash);

failed:
	crypto_free_shash(tfm);
	return ret;
}


static int sha256_test_init(void)
{
	char *data;
	char *out;
	int ret;
	printk("%s invoked\n");
	
	data = kmalloc(ADDR_SIZE, GFP_KERNEL);
	if (!data) {
		printk("no memory for data\n");
		goto err_out;
	}

	out = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
	if (!out) {
		printk("no memory for out\n");
		goto err_out;
	}

	memset(data, 'C', ADDR_SIZE);
	memset(out, 0, SHA256_DIGEST_SIZE);
	
	ret = sha256_test(data, SHA256_DIGEST_SIZE, out);
	if (ret) {
		printk("sha256_test failed with err(%d)\n", ret);
		goto err_out;
	}
	
	printk("shatest:\n");
	for(i = 0; i < SHA256_DIGEST_SIZE; i++)
	{
		printk("idx:%d - %d\n", i, out[i]);
	}
	printk("===========================\n");

	crypto_free_shash(tfm);
	
err_out:
	if (data)
		kfree(data);
	if (out)
		kfree(out);
		
	return err;
}

static void sha256_test_exit(void)
{
	printk("%s invoked\n");
}

module_init(sha256_test_init);
module_exit(sha256_test_exit);

MODULE_LICENSE("GPL");