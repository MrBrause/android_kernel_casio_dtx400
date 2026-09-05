// SPDX-License-Identifier: GPL-2.0
/*
 * hsm_imager.c - Honeywell/Newland N670x 2D imager camera-sensor driver
 *                for the Casio DT-X400 (Point Mobile ODM, MSM8909/APQ8009).
 *
 * Reconstructed by reverse-engineering the stock kernel (CONFIG_HSM=y) with
 * Ghidra + the stock probe dmesg trace, then re-implemented as clean C against
 * the in-tree MSM camera_v2 sensor framework.
 *
 * PHASE A: bind as an I2C driver, run the scanner power sequence, talk to the
 * engine PSoC (I2C 0x40) and the imager (I2C 0x18), detect the N670x, expose
 * the ScanSetting sysfs interface. Reaches the equivalent of the stock
 * "N6703 scanner successfully probed" up to (but not including) the
 * msm_sensor_driver_parse()/v4l2 subdev registration, which is Phase B (marked
 * with TODO(phaseB) below).
 *
 * Hardware facts recovered from the stock driver:
 *   - Engine PSoC on I2C @0x40: write 1-byte command, msleep(5), read N bytes.
 *       cmd 0 -> 4-byte engine id (bit7 of byte0 = "detected"; id e.g. 0x80484E01)
 *       cmd 4 -> 10-byte ASCII serial number
 *   - Imager sensor on I2C @0x18, 16-bit register addresses.
 *       chip-id register 0x3000, expected value 0x0356 => N670x, 1280x800.
 *   - 9 control GPIOs (see enum hsm_gpio_id), some active-low.
 *   - Two regulators: "scan_vio", "scan_v_custom1".
 *   - Power-up also toggles an NXP PCA9535 I/O expander via pca9535c_power_control().
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

/* Phase B: MSM camera_v2 sensor framework (v4l2 capture registration).
 * msm_sensor.h transitively provides <media/v4l2-subdev.h> and
 * msm_camera_i2c.h; cam_soc_api.h provides msm_camera_i2c_dev_get_clk_info().
 * These resolve via the sensor/Makefile ccflags -I paths (camera_v2,
 * camera_v2/common, camera_v2/sensor/io). */
#include "msm_sd.h"
#include "msm_sensor.h"
#include "cam_soc_api.h"
#include "camera.h"		/* camera_init_v4l2() */

#define HSM_DRV_NAME		"hsm_imager"

/* I2C addresses */
#define HSM_ENGINE_PSOC_ADDR	0x40	/* engine command PSoC */
#define HSM_IMAGER_ADDR		0x18	/* N670x imager sensor */

/* Imager chip identification */
#define HSM_N670X_ID_REG	0x3000
#define HSM_N670X_ID_VALUE	0x0356

/* v4l2 subdev name fallback. The name is read from DT "qcom,sensor-name"
 * (generic across variants); this is used only if that property is absent.
 * Matches stock ("n670x <bus>-<addr>") so libHsmKil finds the sensor. */
#define HSM_SENSOR_NAME		"n670x"

/* Engine PSoC commands (1st byte written before the read phase) */
#define HSM_PSOC_CMD_ENGINE_ID	0x00	/* returns 4 bytes */
#define HSM_PSOC_CMD_SERIAL	0x04	/* returns 10 bytes */

/* Power-sequence timing (from the stock trace; conservative where the exact
 * packed delay constant was ambiguous). */
#define HSM_SETTLE_MS		100	/* after power-enable, before detect */
#define HSM_RESET_LOW_MS	1	/* engine-reset asserted */
#define HSM_RESET_SETTLE_MS	120	/* after reset, before re-read */
#define HSM_PSOC_RW_GAP_MS	5	/* between PSoC write and read */

/*
 * Control GPIO identifiers. The index order matches the stock driver's GPIO
 * table and the device-tree "hsm,gpio-*" bindings / qcom,gpio-req-tbl-label.
 */
enum hsm_gpio_id {
	HSM_GPIO_POWER_ENABLE	= 0,	/* SCANNER_POWER_ENABLE */
	HSM_GPIO_AIMER		= 1,	/* SCANNER_AIMER */
	HSM_GPIO_ILLUMINATOR	= 2,	/* SCANNER_ILLUMINATOR */
	HSM_GPIO_ENGINE_RESET	= 3,	/* SCANNER_ENGINE_RESET */
	HSM_GPIO_3V3_LASER	= 4,	/* SCANNER_3V3_LASER */
	HSM_GPIO_3V3_IMAGER	= 5,	/* SCANNER_3V3_IMAGER */
	HSM_GPIO_MIPI_OE	= 6,	/* SCANNER_MIPI_OE */
	HSM_GPIO_MIPI_SEL	= 7,	/* SCANNER_MIPI_SEL */
	HSM_GPIO_FLASH_OUT	= 8,	/* SCANNER_FLASH_OUT */
	HSM_GPIO_COUNT		= 9,
};

/* One control GPIO. Mirrors the 12-byte stock per-GPIO record:
 *   +0x00 label, +0x04 gpio number, +0x08 init value, +0x09 active-low flag. */
struct hsm_gpio {
	const char	*label;
	int		gpio;		/* -1 / >=1024 == not configured */
	u8		init_val;
	u8		active_low;
};

struct hsm_ctrl {
	struct i2c_client	*client;	/* the imager @0x18 */
	struct i2c_adapter	*adap;		/* == client->adapter */
	struct device		*dev;

	struct hsm_gpio		gpio[HSM_GPIO_COUNT];
	u16			gpio_requested;	/* bitmask of currently-requested */

	struct regulator	*vio;		/* scan_vio */
	struct regulator	*vcustom1;	/* scan_v_custom1 */

	bool			supply_on;

	/* engine/imager identification results */
	u8			engine_id[4];
	char			serial[12];
	u16			chip_id;
	u32			width;
	u32			height;
	u8			detected_addr;	/* 0x18 for N670x */

	struct kobject		*kobj;		/* /sys/.../scanner ScanSetting iface */

	/* Phase B: embedded MSM camera sensor framework control. The framework
	 * (msm_sensor_driver_parse) operates on &s_ctrl to register the v4l2
	 * subdev / media entity / capture pipeline. We override only func_tbl
	 * (power ops) because the imager has no DT power-setting array - its
	 * power is the bespoke hsm sequence. */
	struct msm_sensor_ctrl_t	s_ctrl;
	struct msm_sensor_fn_t		func_tbl;
};

#define to_hsm_ctrl(sc) container_of(sc, struct hsm_ctrl, s_ctrl)

/*
 * msm_sensor_driver_parse() is defined in msm_sensor_driver.c. In the stock
 * tree it is file-static; to call it from here it must be exported:
 *   - msm_sensor_driver.c: remove "static" from its definition
 *   - msm_sensor.h: add   int32_t msm_sensor_driver_parse(struct msm_sensor_ctrl_t *);
 * This local prototype lets hsm_imager.c compile; the symbol resolves at link
 * once the "static" is removed (same as the stock hsm driver required).
 */
extern int32_t msm_sensor_driver_parse(struct msm_sensor_ctrl_t *s_ctrl);

/* v4l2 subdev fops for the imager's device node (filled via
 * msm_cam_copy_v4l2_subdev_fops in the subdev-creation step). */
static struct v4l2_file_operations hsm_v4l2_subdev_fops;

/* Forward decl for pca9535c wrapper (separate small driver / this TU).
 * TODO: provide pca9535c_power_control() — wraps the in-tree gpio-pca953x
 * (device_pca953x_init) plus the expander enable GPIOs. Stubbed weak for now
 * so Phase A links even before that wrapper is added. */
int __weak pca9535c_power_control(int on) { return 0; }

/* ------------------------------------------------------------------ */
/* GPIO layer                                                          */
/* ------------------------------------------------------------------ */

static bool hsm_gpio_valid(struct hsm_ctrl *h, unsigned int id)
{
	if (id >= HSM_GPIO_COUNT)
		return false;
	if (!h->gpio[id].label)
		return false;
	if (h->gpio[id].gpio < 0 || h->gpio[id].gpio >= 1024)
		return false;
	return true;
}

static int hsm_gpio_request(struct hsm_ctrl *h, unsigned int id, bool output)
{
	struct hsm_gpio *g;
	int rc;

	if (!hsm_gpio_valid(h, id))
		return -ENXIO;
	g = &h->gpio[id];

	rc = gpio_request(g->gpio, g->label);
	if (rc) {
		dev_err(h->dev, "gpio_request %s (%d) failed: %d\n",
			g->label, g->gpio, rc);
		return rc;
	}
	h->gpio_requested |= (1 << id);

	if (output)
		rc = gpio_direction_output(g->gpio, g->init_val ^ g->active_low);
	else
		rc = gpio_direction_input(g->gpio);
	return rc;
}

static void hsm_gpio_set(struct hsm_ctrl *h, unsigned int id, int value)
{
	if (!hsm_gpio_valid(h, id))
		return;
	/* stock uses raw value XORed with the active-low flag */
	gpio_set_value_cansleep(h->gpio[id].gpio, value ^ h->gpio[id].active_low);
}

static int __maybe_unused hsm_gpio_get(struct hsm_ctrl *h, unsigned int id)
{
	int v;

	if (!hsm_gpio_valid(h, id))
		return -ENXIO;
	v = gpio_get_value_cansleep(h->gpio[id].gpio);
	return v ^ h->gpio[id].active_low;
}

static void hsm_gpio_release(struct hsm_ctrl *h, unsigned int id)
{
	if (!(h->gpio_requested & (1 << id)))
		return;
	if (!hsm_gpio_valid(h, id))
		return;
	h->gpio_requested &= ~(1 << id);
	gpio_free(h->gpio[id].gpio);
}

static void hsm_gpio_free_all(struct hsm_ctrl *h)
{
	unsigned int i;

	for (i = 0; i < HSM_GPIO_COUNT; i++)
		hsm_gpio_release(h, i);
}

/* ------------------------------------------------------------------ */
/* Regulators + power sequence                                         */
/* ------------------------------------------------------------------ */

/*
 * hsm_supply_enable() reproduces the stock power-up / power-down ordering.
 *
 * UP:   regulators on -> 3V3 laser/imager -> pca9535c on -> request gpio 0..3
 *       -> engine-reset pulse -> MIPI oe/sel low (enable MIPI out)
 * DOWN: MIPI oe/sel high -> engine-reset low -> release gpio 0..3
 *       -> pca9535c off -> 3V3 imager/laser off -> regulators off
 */
static int hsm_supply_enable(struct hsm_ctrl *h, bool on)
{
	int rc;

	if (h->supply_on == on)
		return 0;

	if (on) {
		if (h->vio) {
			rc = regulator_enable(h->vio);
			if (rc)
				dev_err(h->dev, "enable scan_vio failed: %d\n", rc);
		}
		if (h->vcustom1) {
			rc = regulator_enable(h->vcustom1);
			if (rc)
				dev_err(h->dev, "enable scan_v_custom1 failed: %d\n", rc);
		}

		hsm_gpio_set(h, HSM_GPIO_3V3_LASER, 1);
		usleep_range(1000, 1500);
		hsm_gpio_set(h, HSM_GPIO_3V3_IMAGER, 1);
		usleep_range(5000, 6000);

		pca9535c_power_control(1);

		hsm_gpio_request(h, HSM_GPIO_POWER_ENABLE, true);
		hsm_gpio_request(h, HSM_GPIO_AIMER, true);
		hsm_gpio_request(h, HSM_GPIO_ILLUMINATOR, true);
		hsm_gpio_request(h, HSM_GPIO_ENGINE_RESET, true);

		/* engine reset pulse */
		usleep_range(1000, 1500);
		hsm_gpio_set(h, HSM_GPIO_ENGINE_RESET, 1);
		msleep(HSM_RESET_LOW_MS);
		hsm_gpio_set(h, HSM_GPIO_ENGINE_RESET, 0);
		msleep(HSM_RESET_SETTLE_MS);

		/* enable MIPI output path */
		hsm_gpio_set(h, HSM_GPIO_MIPI_SEL, 0);
		hsm_gpio_set(h, HSM_GPIO_MIPI_OE, 0);
	} else {
		hsm_gpio_set(h, HSM_GPIO_MIPI_OE, 1);
		hsm_gpio_set(h, HSM_GPIO_MIPI_SEL, 1);
		hsm_gpio_set(h, HSM_GPIO_ENGINE_RESET, 0);

		hsm_gpio_release(h, HSM_GPIO_POWER_ENABLE);
		hsm_gpio_release(h, HSM_GPIO_AIMER);
		hsm_gpio_release(h, HSM_GPIO_ILLUMINATOR);
		hsm_gpio_release(h, HSM_GPIO_ENGINE_RESET);

		pca9535c_power_control(0);
		usleep_range(5000, 6000);

		hsm_gpio_set(h, HSM_GPIO_3V3_IMAGER, 0);
		hsm_gpio_set(h, HSM_GPIO_3V3_LASER, 0);

		if (h->vcustom1)
			regulator_disable(h->vcustom1);
		if (h->vio)
			regulator_disable(h->vio);
	}

	h->supply_on = on;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Engine PSoC protocol (I2C @0x40) and imager register access (@0x18) */
/* ------------------------------------------------------------------ */

/*
 * hsm_psoc_transfer() - write a 1-byte command to the engine PSoC, wait, then
 * read @len bytes of response. Mirrors stock hsm_PsocI2cTransfer().
 */
static int hsm_psoc_transfer(struct i2c_adapter *adap, u8 cmd,
			     u8 *rbuf, u16 len)
{
	struct i2c_msg wr;
	struct i2c_msg rd;
	int rc;

	if (!adap)
		return -ENODEV;

	wr.addr = HSM_ENGINE_PSOC_ADDR;
	wr.flags = 0;
	wr.len = 1;
	wr.buf = &cmd;

	rc = i2c_transfer(adap, &wr, 1);
	if (rc != 1)
		return (rc == -ENXIO) ? -ENXIO : -EIO;

	msleep(HSM_PSOC_RW_GAP_MS);

	rd.addr = HSM_ENGINE_PSOC_ADDR;
	rd.flags = I2C_M_RD;
	rd.len = len;
	rd.buf = rbuf;

	rc = i2c_transfer(adap, &rd, 1);
	if (rc != 1)
		return (rc == -ENXIO) ? -ENXIO : -EIO;

	return 0;
}

/*
 * hsm_read_reg() - read from the imager. For addresses 0x07/0x0e/0x18 the
 * register is 16-bit (big-endian); otherwise 8-bit. Mirrors stock hsm_read_reg.
 */
static int hsm_read_reg(struct i2c_adapter *adap, u8 addr, u16 reg,
			u8 *rbuf, u8 len)
{
	struct i2c_msg msg[2];
	u8 regbuf[2];
	int rc;
	u8 rwidth;

	if (!adap)
		return -ENODEV;

	if (addr == 0x0e || addr == 0x07 || addr == 0x18) {
		rwidth = 2;
		regbuf[0] = (reg >> 8) & 0xff;
		regbuf[1] = reg & 0xff;
	} else {
		rwidth = 1;
		regbuf[0] = reg & 0xff;
	}

	msg[0].addr = addr;
	msg[0].flags = 0;
	msg[0].len = rwidth;
	msg[0].buf = regbuf;

	msg[1].addr = addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = len;
	msg[1].buf = rbuf;

	rc = i2c_transfer(adap, msg, 2);
	if (rc == 2)
		return 0;
	if (rc == -ENXIO)
		return -ENXIO;
	return (rc < 0) ? rc : -EIO;
}

/*
 * hsm_write_reg() - write to the imager (single message: [reg][data...]).
 * Same 16-bit-register rule as read. Mirrors stock hsm_write_reg.
 */
static int __maybe_unused hsm_write_reg(struct i2c_adapter *adap, u8 addr, u16 reg,
			 const u8 *data, u8 len)
{
	struct i2c_msg msg;
	u8 buf[256];
	u8 rwidth;
	int rc;

	if (!adap)
		return -ENODEV;
	if ((size_t)len + 2 > sizeof(buf))
		return -EINVAL;

	if (addr == 0x0e || addr == 0x07 || addr == 0x18) {
		rwidth = 2;
		buf[0] = (reg >> 8) & 0xff;
		buf[1] = reg & 0xff;
	} else {
		rwidth = 1;
		buf[0] = reg & 0xff;
	}
	memcpy(buf + rwidth, data, len);

	msg.addr = addr;
	msg.flags = 0;
	msg.len = rwidth + len;
	msg.buf = buf;

	rc = i2c_transfer(adap, &msg, 1);
	if (rc == 1)
		return 0;
	return (rc < 0) ? rc : -EIO;
}

/* ------------------------------------------------------------------ */
/* Engine detection                                                    */
/* ------------------------------------------------------------------ */

/* Query the engine PSoC for its id and serial. Mirrors hsm_CheckEngineType. */
static int hsm_check_engine_type(struct hsm_ctrl *h)
{
	u8 id[4] = { 0 };
	char serial[11] = { 0 };
	int rc;

	rc = hsm_psoc_transfer(h->adap, HSM_PSOC_CMD_ENGINE_ID, id, sizeof(id));
	if (rc) {
		dev_err(h->dev, "engine-id read failed: %d\n", rc);
		return rc;
	}
	memcpy(h->engine_id, id, sizeof(id));
	dev_info(h->dev, "engine id = %02x %02x %02x %02x (%sdetected)\n",
		 id[0], id[1], id[2], id[3], (id[0] & 0x80) ? "" : "NOT ");

	rc = hsm_psoc_transfer(h->adap, HSM_PSOC_CMD_SERIAL, serial, 10);
	if (rc == 0) {
		serial[10] = '\0';
		strlcpy(h->serial, serial, sizeof(h->serial));
		dev_info(h->dev, "engine serial = %s\n", h->serial);
	}
	return 0;
}

/*
 * Confirm the N670x by reading the 16-bit chip-id register 0x3000 over the
 * imager I2C address; expect 0x0356. Includes the stock reset-and-retry.
 * Mirrors the N670x branch of hsm_probe / hsm_IsN670x.
 */
static int hsm_detect_n670x(struct hsm_ctrl *h)
{
	u8 val[2] = { 0 };
	u16 id;
	int rc;

	rc = hsm_read_reg(h->adap, HSM_IMAGER_ADDR, HSM_N670X_ID_REG, val, 2);
	if (rc) {
		dev_info(h->dev, "chip-id read failed (%d); reset + retry\n", rc);
		hsm_gpio_set(h, HSM_GPIO_ENGINE_RESET, 1);
		msleep(HSM_RESET_LOW_MS);
		hsm_gpio_set(h, HSM_GPIO_ENGINE_RESET, 0);
		msleep(HSM_RESET_SETTLE_MS);
		rc = hsm_read_reg(h->adap, HSM_IMAGER_ADDR, HSM_N670X_ID_REG,
				  val, 2);
		if (rc) {
			dev_err(h->dev, "chip-id retry failed: %d\n", rc);
			return rc;
		}
	}

	/* stock byte-swaps the 16-bit value */
	id = (val[0] << 8) | val[1];
	if (id != HSM_N670X_ID_VALUE) {
		dev_err(h->dev, "unexpected chip id 0x%04x (want 0x%04x)\n",
			id, HSM_N670X_ID_VALUE);
		return -ENODEV;
	}

	h->chip_id = id;
	h->detected_addr = HSM_IMAGER_ADDR;
	h->width = 1280;	/* 0x500 */
	h->height = 800;
	dev_info(h->dev, "N670x detected: chip id 0x%04x, %ux%u\n",
		 h->chip_id, h->width, h->height);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Device-tree GPIO parsing                                            */
/* ------------------------------------------------------------------ */

static const struct {
	enum hsm_gpio_id id;
	const char *prop;
	const char *label;
} hsm_gpio_dt[] = {
	{ HSM_GPIO_POWER_ENABLE, "hsm,gpio-power-enable",  "SCANNER_POWER_ENABLE" },
	{ HSM_GPIO_AIMER,	 "hsm,gpio-aimer",	   "SCANNER_AIMER" },
	{ HSM_GPIO_ILLUMINATOR,	 "hsm,gpio-illuminator",   "SCANNER_ILLUMINATOR" },
	{ HSM_GPIO_ENGINE_RESET, "hsm,gpio-engine-reset",  "SCANNER_ENGINE_RESET" },
	{ HSM_GPIO_3V3_LASER,	 "hsm,gpio-3v3-laser",	   "SCANNER_3V3_LASER" },
	{ HSM_GPIO_3V3_IMAGER,	 "hsm,gpio-3v3-imager",	   "SCANNER_3V3_IMAGER" },
	{ HSM_GPIO_MIPI_OE,	 "hsm,gpio-mipi-oe",	   "SCANNER_MIPI_OE" },
	{ HSM_GPIO_MIPI_SEL,	 "hsm,gpio-mipi-sel",	   "SCANNER_MIPI_SEL" },
	{ HSM_GPIO_FLASH_OUT,	 "hsm,gpio-flash-out",	   "SCANNER_FLASH_OUT" },
};

/*
 * The stock set_gpio_table() reads a 3-cell "hsm,gpio-*" property:
 *   <phandle-index-into-"gpios" init-value active-low>
 * then resolves the actual gpio via of_get_named_gpio_flags(of_node, "gpios",
 * <index>). We follow the same scheme: cell0 = index into the "gpios" array,
 * cell1 = init value, cell2 = active-low.
 */
/*
 * Returns 0 on success, or -EPROBE_DEFER if a GPIO cannot be resolved yet.
 *
 * On the DT-X400-20 the "gpios" list spans two controllers: the SoC TLMM (the
 * engine control lines, entries 0..3) and the NXP PCA9535 I/O expander (the
 * rail/MIPI lines, entries 4..8, controller phandle 0xfe). The expander pins
 * only resolve once gpio-pca953x has probed and registered its gpiochip, so if
 * of_get_named_gpio() returns -EPROBE_DEFER we propagate it and let the kernel
 * retry hsm_probe() after the expander is up.
 */
static int hsm_parse_gpios(struct hsm_ctrl *h, struct device_node *np)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(hsm_gpio_dt); i++) {
		enum hsm_gpio_id id = hsm_gpio_dt[i].id;
		u32 cells[3];
		int gpio;

		h->gpio[id].gpio = -1;
		h->gpio[id].label = NULL;

		if (of_property_read_u32_array(np, hsm_gpio_dt[i].prop,
					       cells, 3) < 0)
			continue;

		gpio = of_get_named_gpio(np, "gpios", cells[0]);
		if (gpio == -EPROBE_DEFER) {
			dev_info(h->dev, "%s: gpios[%u] not ready, deferring\n",
				 hsm_gpio_dt[i].prop, cells[0]);
			return -EPROBE_DEFER;
		}
		if (!gpio_is_valid(gpio)) {
			dev_warn(h->dev, "%s: gpios[%u] invalid\n",
				 hsm_gpio_dt[i].prop, cells[0]);
			continue;
		}

		h->gpio[id].gpio = gpio;
		h->gpio[id].init_val = cells[1] ? 1 : 0;
		h->gpio[id].active_low = cells[2] ? 1 : 0;
		h->gpio[id].label = hsm_gpio_dt[i].label;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* sysfs (ScanSetting control interface) — Phase A: identity read-only */
/* ------------------------------------------------------------------ */

static struct hsm_ctrl *g_hsm;	/* single instance, like the stock driver */

static ssize_t hsm_serial_show(struct kobject *k, struct kobj_attribute *a,
			       char *buf)
{
	if (!g_hsm)
		return -ENODEV;
	return scnprintf(buf, PAGE_SIZE, "%s\n", g_hsm->serial);
}

static ssize_t hsm_chipid_show(struct kobject *k, struct kobj_attribute *a,
			       char *buf)
{
	if (!g_hsm)
		return -ENODEV;
	return scnprintf(buf, PAGE_SIZE, "0x%04x\n", g_hsm->chip_id);
}

static struct kobj_attribute hsm_attr_serial =
	__ATTR(serial, 0444, hsm_serial_show, NULL);
static struct kobj_attribute hsm_attr_chipid =
	__ATTR(chip_id, 0444, hsm_chipid_show, NULL);

/* TODO(phaseB): the stock driver creates 7 sysfs files here (the full
 * ScanSetting control surface: aimer, illuminator, trigger, etc.). Phase A
 * exposes just identity attributes to confirm detection from userspace. */

static int hsm_sysfs_create(struct hsm_ctrl *h)
{
	int rc;

	h->kobj = kobject_create_and_add("scanner", NULL);
	if (!h->kobj)
		return -ENOMEM;

	rc = sysfs_create_file(h->kobj, &hsm_attr_serial.attr);
	if (rc)
		goto err;
	rc = sysfs_create_file(h->kobj, &hsm_attr_chipid.attr);
	if (rc) {
		sysfs_remove_file(h->kobj, &hsm_attr_serial.attr);
		goto err;
	}
	return 0;
err:
	kobject_put(h->kobj);
	h->kobj = NULL;
	return rc;
}

static void hsm_sysfs_remove(struct hsm_ctrl *h)
{
	if (!h->kobj)
		return;
	sysfs_remove_file(h->kobj, &hsm_attr_chipid.attr);
	sysfs_remove_file(h->kobj, &hsm_attr_serial.attr);
	kobject_put(h->kobj);
	h->kobj = NULL;
}

/* ------------------------------------------------------------------ */
/* Phase B: MSM camera sensor framework integration                    */
/* ------------------------------------------------------------------ */

/*
 * Custom power ops. The framework's default subdev .s_power (msm_sensor_power)
 * routes to func_tbl->sensor_power_up/down. Because the imager has no DT
 * power-setting array, we wire the real hsm power sequence here (reusing the
 * Phase A helpers).
 */
static int hsm_sensor_power_up(struct msm_sensor_ctrl_t *s_ctrl)
{
	struct hsm_ctrl *h = to_hsm_ctrl(s_ctrl);
	int rc;

	dev_info(h->dev, "hsm_sensor_power_up\n");
	rc = hsm_supply_enable(h, true);
	if (rc) {
		dev_err(h->dev, "power_up: supply enable failed %d\n", rc);
		return rc;
	}
	hsm_gpio_set(h, HSM_GPIO_POWER_ENABLE, 1);
	msleep(HSM_SETTLE_MS);
	return 0;
}

static int hsm_sensor_power_down(struct msm_sensor_ctrl_t *s_ctrl)
{
	struct hsm_ctrl *h = to_hsm_ctrl(s_ctrl);

	dev_info(h->dev, "hsm_sensor_power_down\n");
	hsm_gpio_set(h, HSM_GPIO_POWER_ENABLE, 0);
	hsm_supply_enable(h, false);
	return 0;
}

static int hsm_sensor_match_id(struct msm_sensor_ctrl_t *s_ctrl)
{
	struct hsm_ctrl *h = to_hsm_ctrl(s_ctrl);

	if (h->chip_id == HSM_N670X_ID_VALUE)
		return 0;
	dev_err(h->dev, "match_id: chip 0x%04x != 0x%04x\n",
		h->chip_id, HSM_N670X_ID_VALUE);
	return -ENODEV;
}

/*
 * Register the (already-detected) imager with the MSM camera sensor framework
 * so it appears as a v4l2 subdev the capture pipeline / libHsmKil can stream.
 * Verbose logging pinpoints where msm_sensor_driver_parse fails on first probe
 * (most likely DT parsing of the imager node).
 */
static int hsm_register_msm_sensor(struct hsm_ctrl *h)
{
	struct msm_sensor_ctrl_t *s = &h->s_ctrl;
	int rc;

	dev_info(h->dev, "hsm_register_msm_sensor: begin\n");

	s->of_node            = h->client->dev.of_node;
	s->sensor_device_type = MSM_CAMERA_I2C_DEVICE;

	/* Override only the power/match ops; leave subdev_ops + i2c_func_tbl
	 * NULL so msm_sensor_init_default_params() fills framework defaults. */
	h->func_tbl.sensor_power_up   = hsm_sensor_power_up;
	h->func_tbl.sensor_power_down = hsm_sensor_power_down;
	h->func_tbl.sensor_match_id   = hsm_sensor_match_id;
	s->func_tbl = &h->func_tbl;

	dev_info(h->dev, "hsm_register_msm_sensor: msm_sensor_driver_parse\n");
	rc = msm_sensor_driver_parse(s);
	if (rc < 0) {
		dev_err(h->dev, "msm_sensor_driver_parse failed: %d\n", rc);
		return rc;
	}
	dev_info(h->dev, "hsm_register_msm_sensor: parse OK id=%u\n", s->id);

	if (s->sensor_i2c_client) {
		s->sensor_i2c_client->client = h->client;
		if (s->sensordata)
			s->sensordata->power_info.dev = &h->client->dev;

		rc = msm_camera_i2c_dev_get_clk_info(
			&s->sensor_i2c_client->client->dev,
			&s->sensordata->power_info.clk_info,
			&s->sensordata->power_info.clk_ptr,
			&s->sensordata->power_info.clk_info_size);
		if (rc < 0) {
			dev_err(h->dev, "i2c_dev_get_clk_info failed: %d\n", rc);
			return rc;
		}
	}

	/*
	 * Create the v4l2 subdev device node. This replicates the framework's
	 * static msm_sensor_driver_create_i2c_v4l_subdev() (i2c variant), which
	 * msm_sensor_driver_parse() does NOT do itself. Without this the sensor
	 * is registered in g_sctrl[] but no /dev/v4l-subdevN node appears.
	 * msm_sd_register / camera_init_v4l2 / msm_cam_copy_v4l2_subdev_fops are
	 * all exported (msm_sd.h, camera/camera.h).
	 */
	{
		uint32_t session_id = 0;

		if (!s->bypass_video_node_creation) {
			rc = camera_init_v4l2(&h->client->dev, &session_id);
			if (rc < 0) {
				dev_err(h->dev, "camera_init_v4l2 failed: %d\n", rc);
				return rc;
			}
		}

		/*
		 * Determine the v4l2 subdev name. Prefer the DT "qcom,sensor-name"
		 * (keeps the driver generic across engine variants); fall back to
		 * HSM_SENSOR_NAME. The framework's sensordata->sensor_name comes
		 * back NULL from parse on this node, so we read the DT directly.
		 */
		{
			const char *sname = NULL;

			of_property_read_string(h->client->dev.of_node,
						"qcom,sensor-name", &sname);
			if (!sname || !sname[0])
				sname = HSM_SENSOR_NAME;

			snprintf(s->msm_sd.sd.name, sizeof(s->msm_sd.sd.name),
				 "%s", sname);
			v4l2_i2c_subdev_init(&s->msm_sd.sd, h->client,
					     s->sensor_v4l2_subdev_ops);
			/*
			 * v4l2_i2c_subdev_init() overwrites sd.name with the i2c
			 * driver name ("hsm_imager <bus>-<addr>"). Stock exposes
			 * the sensor as "<sensor-name> <bus>-<addr>" and libHsmKil
			 * may look it up by that name, so force it back.
			 */
			snprintf(s->msm_sd.sd.name, sizeof(s->msm_sd.sd.name),
				 "%s %d-%04x", sname,
				 i2c_adapter_id(h->client->adapter),
				 h->client->addr);
		}
		v4l2_set_subdevdata(&s->msm_sd.sd, h->client);
		s->msm_sd.sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
		media_entity_init(&s->msm_sd.sd.entity, 0, NULL, 0);
		s->msm_sd.sd.entity.type = MEDIA_ENT_T_V4L2_SUBDEV;
		s->msm_sd.sd.entity.group_id = MSM_CAMERA_SUBDEV_SENSOR;
		s->msm_sd.sd.entity.name = s->msm_sd.sd.name;
		if (s->sensordata->sensor_info)
			s->sensordata->sensor_info->session_id = session_id;
		s->msm_sd.close_seq = MSM_SD_CLOSE_2ND_CATEGORY | 0x3;

		rc = msm_sd_register(&s->msm_sd);
		if (rc < 0) {
			dev_err(h->dev, "msm_sd_register failed: %d\n", rc);
			return rc;
		}
		msm_cam_copy_v4l2_subdev_fops(&hsm_v4l2_subdev_fops);
		s->msm_sd.sd.devnode->fops = &hsm_v4l2_subdev_fops;
		dev_info(h->dev, "v4l2 subdev '%s' registered (session %u)\n",
			 s->msm_sd.sd.name, session_id);
	}

	dev_info(h->dev, "hsm_register_msm_sensor: SUCCESS (n670x registered)\n");
	return 0;
}

/* ------------------------------------------------------------------ */
/* Probe / remove                                                      */
/* ------------------------------------------------------------------ */

static int hsm_probe(struct i2c_client *client,
		     const struct i2c_device_id *id)
{
	struct hsm_ctrl *h;
	struct device_node *np = client->dev.of_node;
	int rc;

	dev_info(&client->dev, "hsm_probe: name=imager, address=0x%02x\n",
		 client->addr);

	if (!np) {
		dev_err(&client->dev, "no device-tree node\n");
		return -EINVAL;
	}

	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return -ENOMEM;

	h->client = client;
	h->adap = client->adapter;
	h->dev = &client->dev;
	i2c_set_clientdata(client, h);

	/* regulators (optional; some boards route power differently) */
	h->vio = regulator_get(h->dev, "scan_vio");
	if (IS_ERR(h->vio)) {
		dev_warn(h->dev, "scan_vio not available: %ld\n", PTR_ERR(h->vio));
		h->vio = NULL;
	}
	h->vcustom1 = regulator_get(h->dev, "scan_v_custom1");
	if (IS_ERR(h->vcustom1)) {
		dev_warn(h->dev, "scan_v_custom1 not available: %ld\n",
			 PTR_ERR(h->vcustom1));
		h->vcustom1 = NULL;
	}

	rc = hsm_parse_gpios(h, np);
	if (rc == -EPROBE_DEFER) {
		/* PCA9535 expander not up yet; retry later. */
		if (h->vio)
			regulator_put(h->vio);
		if (h->vcustom1)
			regulator_put(h->vcustom1);
		i2c_set_clientdata(client, NULL);
		kfree(h);
		return -EPROBE_DEFER;
	}

	/* request the always-needed GPIOs for power sequencing.
	 * (POWER_ENABLE/AIMER/ILLUMINATOR/ENGINE_RESET are requested inside
	 * hsm_supply_enable; here we grab the rail + MIPI + flash controls.) */
	{
		static const struct {
			enum hsm_gpio_id id;
			bool output;
		} req[] = {
			{ HSM_GPIO_FLASH_OUT,	false },
			{ HSM_GPIO_MIPI_OE,	true },
			{ HSM_GPIO_MIPI_SEL,	true },
			{ HSM_GPIO_3V3_IMAGER,	true },
			{ HSM_GPIO_3V3_LASER,	true },
		};
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(req); i++) {
			rc = hsm_gpio_request(h, req[i].id, req[i].output);
			if (rc) {
				dev_err(h->dev, "gpio request (id %d) failed: %d\n",
					req[i].id, rc);
				goto err_gpio;
			}
		}
	}

	/* power up for detection */
	hsm_supply_enable(h, true);
	hsm_gpio_set(h, HSM_GPIO_POWER_ENABLE, 1);
	msleep(HSM_SETTLE_MS);

	rc = hsm_check_engine_type(h);
	if (rc) {
		dev_err(h->dev, "engine detection failed: %d\n", rc);
		goto err_power;
	}

	rc = hsm_detect_n670x(h);
	if (rc) {
		dev_err(h->dev, "N670x detection failed: %d\n", rc);
		goto err_power;
	}

	g_hsm = h;

	rc = hsm_sysfs_create(h);
	if (rc)
		dev_warn(h->dev, "sysfs create failed: %d (continuing)\n", rc);

	/*
	 * Phase B: register with the MSM camera_v2 sensor framework so the
	 * imager appears as a v4l2 subdev (n670x <bus>-0018) that the capture
	 * pipeline / libHsmKil can stream from.
	 */
	rc = hsm_register_msm_sensor(h);
	if (rc) {
		dev_err(h->dev, "msm_sensor registration failed: %d\n", rc);
		goto err_power;
	}

	/*
	 * Stock powers the engine DOWN after a successful probe; the framework
	 * powers it back up for capture via func_tbl->sensor_power_up.
	 */
	hsm_gpio_set(h, HSM_GPIO_POWER_ENABLE, 0);
	hsm_supply_enable(h, false);

	/* NOTE: do NOT free h on success - the embedded s_ctrl is now
	 * registered with the framework (referenced via g_sctrl[]). h lives
	 * for the driver lifetime (held via i2c_set_clientdata). */
	dev_info(h->dev, "N670x scanner successfully probed (Phase B, registered)\n");
	return 0;

err_power:
	hsm_gpio_set(h, HSM_GPIO_POWER_ENABLE, 0);
	hsm_supply_enable(h, false);
err_gpio:
	hsm_gpio_free_all(h);
	if (h->vio)
		regulator_put(h->vio);
	if (h->vcustom1)
		regulator_put(h->vcustom1);
	i2c_set_clientdata(client, NULL);
	kfree(h);
	return rc;
}

static int hsm_remove(struct i2c_client *client)
{
	struct hsm_ctrl *h = i2c_get_clientdata(client);

	if (!h)
		return 0;
	hsm_sysfs_remove(h);
	hsm_supply_enable(h, false);
	hsm_gpio_free_all(h);
	if (h->vio)
		regulator_put(h->vio);
	if (h->vcustom1)
		regulator_put(h->vcustom1);
	if (g_hsm == h)
		g_hsm = NULL;
	kfree(h);
	return 0;
}

static const struct i2c_device_id hsm_id[] = {
	{ "n670x", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, hsm_id);

static const struct of_device_id hsm_of_match[] = {
	{ .compatible = "hsm,imager" },
	{ }
};
MODULE_DEVICE_TABLE(of, hsm_of_match);

static struct i2c_driver hsm_i2c_driver = {
	.driver = {
		.name = HSM_DRV_NAME,
		.owner = THIS_MODULE,
		.of_match_table = hsm_of_match,
	},
	.probe = hsm_probe,
	.remove = hsm_remove,
	.id_table = hsm_id,
};

static int __init hsm_module_init(void)
{
	pr_info("hsm_imager: init\n");
	return i2c_add_driver(&hsm_i2c_driver);
}

static void __exit hsm_module_exit(void)
{
	i2c_del_driver(&hsm_i2c_driver);
}

module_init(hsm_module_init);
module_exit(hsm_module_exit);

MODULE_DESCRIPTION("Honeywell/Newland N670x imager (Casio DT-X400) - Phase B msm_sensor");
MODULE_LICENSE("GPL v2");
