#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/time.h>

/* This is the string representation of SHA1(CT password) */
#define CT_HMAC_KEY	"5619d0694cf2dbb2317ece65734f9f501cb3e39f"
#define CT_HMAC_KEY_SZ	40

#define BOOT_PART_NAME	"/dev/block/platform/mtk-msdc.0/by-name/boot"

/* Boot IMG header
 * Taken from platform/mt6752/include/platform.h in LK code */
#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8

struct boot_img_hdr {
	unsigned char magic[BOOT_MAGIC_SIZE];

	unsigned kernel_size;
	unsigned kernel_addr;
	unsigned ramdisk_size;
	unsigned ramdisk_addr;
	unsigned second_size;
	unsigned second_addr;
	unsigned tags_addr;
	unsigned page_size;
};

#define SHA1_SIZE       20
#define KEYPAD_SIZE     64

struct ct_hmac {
    u8 i_keypad[KEYPAD_SIZE];
    u8 o_keypad[KEYPAD_SIZE];
    struct shash_desc sd;
};

static struct ct_hmac * ct_alloc_hmac(void);
static int ct_hmac_init(struct ct_hmac *hmac, const u8 *key,
        unsigned int keylen);
static int ct_hmac_update(struct ct_hmac *hmac, const u8 *data,
        unsigned int len);
static int ct_hmac_final(struct ct_hmac *hmac, u8 *out);
static void ct_free_hmac(struct ct_hmac *hmac);
static u64 ct_get_boottime(void);

struct kobject *communitake_kobj;
EXPORT_SYMBOL_GPL(communitake_kobj);

unsigned int get_boot_img_size(struct boot_img_hdr *hdr)
{
	unsigned int size;

	/* Validate Magic */
	if (strncmp(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
		pr_err("Not Boot Image (Magic not found)");
		return 0;
	}

	if (hdr->second_size) {
		pr_err("Invalid Boot Image (second_size!=0)");
		return 0;
	}

	/* Partition hdr starts at 0, so first aligned address for kernel image
	   is at 'page_size' */
	size = hdr->page_size;

	/* Add kernel image size */
	size += hdr->kernel_size;

	/* Align address to page boundary */
	if (size & (hdr->page_size - 1)) {
		size &= ~(hdr->page_size - 1);
		size += hdr->page_size;
	}

	/* Add rootfs image size */
	size += hdr->ramdisk_size;

	/* Align address to page boundary */
	if (size & (hdr->page_size - 1)) {
		size &= ~(hdr->page_size - 1);
		size += hdr->page_size;
	}

	return size;
}

static int gen_boot_signatures(u8 *sha1, u8 *hmac)
{
	struct file *fp = NULL;
	mm_segment_t oldfs;
	int data_size = 0;
	loff_t offset = 0;
	char data[1024];
	unsigned int total = 0;
	unsigned int part_size;
	u64 boot_time;

	struct shash_desc *sd = NULL;
	struct crypto_shash *shash = NULL;
	struct ct_hmac *hmac_ctx = NULL;

	/* Alloc and init crypto sha1 hash */
	shash = crypto_alloc_shash("sha1", 0, 0);
	if (!shash) {
		pr_err("Failed to allocate shash\n");
		return 0;
	}

	sd = (struct shash_desc *) kmalloc(sizeof(struct shash_desc) +
					   crypto_shash_descsize(shash),
					   GFP_KERNEL);
	if (!sd) {
		pr_err("Failed to allocate shash_desc\n");
		goto Exit;
	}

	sd->tfm = shash;
	sd->flags = 0;

	if (crypto_shash_init(sd)) {
		pr_err("shash_init failed\n");
		goto Exit;
	}

	/* Alloc and init hmac */
	hmac_ctx = ct_alloc_hmac();
	if (!hmac_ctx) {
		pr_err("alloc_hmac failed\n");
		goto Exit;
	}

	if (ct_hmac_init(hmac_ctx, CT_HMAC_KEY, CT_HMAC_KEY_SZ)) {
		pr_err("hmac_init failed\n");
		goto Exit;
	}

	/* Open boot partition dev node */
	fp = filp_open(BOOT_PART_NAME, O_RDONLY, 0);
	if (!fp) {
		pr_err("Failed to open boot patition\n");
		goto Exit;
	}

	/* Read first block of data with partition header */
	oldfs = get_fs();
	set_fs(get_ds());

	data_size = vfs_read(fp, data, sizeof(data), &offset);

	set_fs(oldfs);

	/* Make sure we have enough to parse header (if the first read is
	 * partial we've failed anyway so test for all of it */
	if (data_size != sizeof(data)) {
		pr_err("vfs_read failed (%u/%lu)\n", data_size, sizeof(data));
		goto Exit;
	}

	/* Verify parition and obtain its size */
	part_size = get_boot_img_size((struct boot_img_hdr *)data);
	if (!part_size) {
		pr_err("Invalid partition\n");
		total = 0;
		goto Exit;
	}

	pr_debug("Boot partition size: %u\n", part_size);

	/* Read the rest and generate hash */

	while (data_size && total < part_size) {
		/* For proper form. Should not happen since buf_size is ai
		   multiple of page_size */
		if (total + data_size > part_size) {
			data_size = part_size - total;
		}

		total += data_size;

		if (crypto_shash_update(sd, data, data_size)) {
			pr_err("shash_update failed\n");
			total = 0;
			goto Exit;
		}

		if (ct_hmac_update(hmac_ctx, data, data_size)) {
			pr_err("hmac_update failed\n");
			total = 0;
			goto Exit;
		}

		oldfs = get_fs();
		set_fs(get_ds());

		data_size = vfs_read(fp, data, sizeof(data), &offset);

		set_fs(oldfs);
	}

	/* Before finishing, add boot time to the hmac */
	boot_time = ct_get_boottime();
	if (ct_hmac_update(hmac_ctx, (const u8 *)&boot_time, sizeof(boot_time))) {
		pr_err("shash_update failed\n");
		total = 0;
		goto Exit;
	}

	if (crypto_shash_final(sd, sha1)) {
			pr_err("shash_final failed\n");
			total = 0;
			goto Exit;
	}

	if (ct_hmac_final(hmac_ctx, hmac)) {
			pr_err("hmac_final failed\n");
			total = 0;
			goto Exit;
	}

	pr_debug("Total bytes read: %u\n", total);

Exit:
	if (fp)
		filp_close(fp, 0);

	if (sd) {
		if (sd->tfm)
			crypto_free_shash(sd->tfm);

		kfree(sd);
	}

	if (hmac_ctx)
		ct_free_hmac(hmac_ctx);

	return total;
}

#define INC_BUF(size)	\
	buf += (size);	\
	total += (size);

static ssize_t sboot_fp_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	ssize_t total = 0;
	unsigned int size;
	u8 sha1[SHA1_SIZE];
	u8 hmac[SHA1_SIZE];
	int i;

	memset(sha1, 0xCC, sizeof(sha1));
	memset(hmac, 0xCC, sizeof(hmac));

	if (!gen_boot_signatures(sha1, hmac))
		return 0;

	for (i = 0; i < sizeof(sha1); i++) {
		size = sprintf(buf, "%02x", sha1[i]);
		INC_BUF(size);
	}

	size = sprintf(buf, "\n");
	INC_BUF(size);

	for (i = 0; i < sizeof(hmac); i++) {
		size = sprintf(buf, "%02x", hmac[i]);
		INC_BUF(size);
	}

	size = sprintf(buf, "\n");
	INC_BUF(size);
	return total;
}

#undef INC_BUF

static ssize_t sboot_fp_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	return 0;
}

static struct kobj_attribute sboot_fp_attr =
	__ATTR(sboot_fp, 0440, sboot_fp_show, sboot_fp_store);

int communitake_sysfs_init (void)
{
	int rc;

	communitake_kobj = kobject_create_and_add("communitake", kernel_kobj);
	if(!communitake_kobj) {
		pr_err("failed to create /sys/kernel/communitake \n");
		rc = -ENOMEM;
		goto Exit;
	}

	rc = sysfs_create_file(communitake_kobj, &sboot_fp_attr.attr);
	if (rc) {
		pr_err("failed to create /sys/kernel/communitake/sboot_fp \n");
		goto Exit;
	}

	rc = 0;

Exit:
	/* We keep ct_kobj in any case so others can use it */
	return rc;
}

EXPORT_SYMBOL(communitake_sysfs_init);

/*============= Our HMAC implementation ============ */

static struct ct_hmac * ct_alloc_hmac(void)
{
	struct ct_hmac *hmac;
	struct crypto_shash *shash;

	pr_debug("ct_alloc_hmac: entered\n");

	shash = crypto_alloc_shash("sha1", 0, 0);
	if (!shash) {
		return NULL;
	}

	hmac = (struct ct_hmac *) kmalloc(sizeof(struct ct_hmac) +
					  crypto_shash_descsize(shash),
					  GFP_KERNEL);
	if (!hmac) {
		crypto_free_shash(shash);
		return NULL;
	}

	hmac->sd.tfm = shash;
	hmac->sd.flags = 0;

	pr_debug("ct_alloc_hmac: leaving. hmac = %p\n", hmac);
	return hmac;
}

static int ct_hmac_init(struct ct_hmac *hmac, const u8 *key,
			unsigned int keylen)
{
	int rc;
	int i;

	pr_debug("ct_hmac_init: entered\n");

	/* Init key pads */
	memset(hmac->i_keypad, 0x36, sizeof(hmac->i_keypad));
	memset(hmac->o_keypad, 0x5c, sizeof(hmac->o_keypad));

	/* TODO: handle keylen > 64 by hashing key */
	if (keylen > KEYPAD_SIZE)
		return -1;

	for (i = 0; i < keylen; i++) {
		hmac->i_keypad[i] ^= key[i];
		hmac->o_keypad[i] ^= key[i];
	}

	/* Init shash */
	rc = crypto_shash_init(&hmac->sd);
	if (rc < 0)
		goto Exit;

	/* Hash i_keypad */
	rc = crypto_shash_update(&hmac->sd, hmac->i_keypad,
				 sizeof(hmac->i_keypad));

Exit:
	pr_debug("ct_hmac_init: leaving. rc = %d\n", rc);
	return rc;
}

static int ct_hmac_update(struct ct_hmac *hmac, const u8 *data,
			  unsigned int len)
{
	int rc;
	pr_debug("ct_hmac_update: entered\n");
	rc = crypto_shash_update(&hmac->sd, data, len);
	pr_debug("ct_hmac_update: leaving. rc = %d\n", rc);
	return rc;
}

static int ct_hmac_final(struct ct_hmac *hmac, u8 *out)
{
	u8 i_sha1[SHA1_SIZE];
	int rc;

	pr_debug("ct_hmac_final: entered\n");

	/* Finalize first pass */
	rc = crypto_shash_final(&hmac->sd, i_sha1);
	if (rc < 0)
		goto Exit;

	/* Perform second pass */

	/* Init shash */
	rc = crypto_shash_init(&hmac->sd);
	if (rc < 0)
		goto Exit;

	/* Hash o_kaypad */
	rc = crypto_shash_update(&hmac->sd, hmac->o_keypad,
				 sizeof(hmac->o_keypad));
	if (rc < 0)
		goto Exit;

	/* Hash first pass sha1 */
	rc = crypto_shash_update(&hmac->sd, i_sha1, sizeof(i_sha1));
	if (rc < 0)
		goto Exit;

	/* Finalize second pass */
	rc = crypto_shash_final(&hmac->sd, out);

Exit:
	pr_debug("ct_hmac_final: leaving. rc = %d\n", rc);
	return rc;
}

static void ct_free_hmac(struct ct_hmac *hmac)
{
	if (hmac) {
		if (hmac->sd.tfm)
			crypto_free_shash(hmac->sd.tfm);

		kfree(hmac);
	}
}

static u64 ct_get_boottime()
{
	struct tm tm;
	struct timespec ts;

	getboottime(&ts);			  /* Get time of boot */
	ts.tv_sec -= sys_tz.tz_minuteswest * 60;  /* Adjust for timezone */

	time_to_tm(ts.tv_sec, 0, &tm);
	pr_debug("boottime: %lu  (tz: %d, dst: %d)\n", ts.tv_sec,
		 sys_tz.tz_minuteswest, sys_tz.tz_dsttime);
	pr_debug(" @ (%04ld-%02d-%02d %02d:%02d:%02d)\n",
	       tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
	       tm.tm_min, tm.tm_sec);

	return (u64)ts.tv_sec;
}

