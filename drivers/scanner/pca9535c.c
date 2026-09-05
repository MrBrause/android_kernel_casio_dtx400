// SPDX-License-Identifier: GPL-2.0
/*
 * pca9535c.c - bring up the Casio DT-X400 scanner I/O expander (pca9535@25).
 *
 * BACKGROUND
 * ----------
 * The scanner's engine-control GPIOs (SCANNER_POWER_ENABLE, AIMER,
 * ILLUMINATOR, ENGINE_RESET) live on a fourth NXP PCA9535 I/O expander at
 * i2c address 0x25 (device-tree node pca9535@25, phandle 0x10e). Unlike the
 * other three expanders (@20/@22/@24), @25 is powered through a level shifter
 * whose enable lines are two GPIOs on the @22 expander:
 *
 *     gpio-pca9535c-en     = <&pca9535_22 10 0>   (@22 GPIO 10)
 *     gpio-level-shift1-en = <&pca9535_22 14 0>   (@22 GPIO 14)
 *
 * Until both are driven high, @25 does not answer on i2c (NACK, -107), so the
 * standard gpio-pca953x driver's subsys_initcall probe of @25 fails and its
 * gpiochip is never registered - which in turn leaves the hsm_imager sensor
 * driver deferring forever on SCANNER_POWER_ENABLE.
 *
 * The stock firmware carried @25 as status="disabled" and brought it up from a
 * vendor driver (pca9535c_enable -> device_pca953x_init) after driving those
 * enable lines. That vendor driver was never published; this file reproduces
 * the essential step.
 *
 * WHAT THIS DOES
 * --------------
 * At late_initcall (after gpio-pca953x's subsys_initcall has registered @22):
 *   1. resolve @25's two enable GPIOs (they reference @22, now up) and drive
 *      them high,
 *   2. re-attach the @25 i2c device so gpio-pca953x probes it again - this
 *      time it answers, registers its gpiochip, and the scanner GPIOs become
 *      available.
 *
 * This is the in-kernel equivalent of the manual bring-up that was verified to
 * work from userspace:
 *     echo 1 > .../@22-gpio-10 ; echo 1 > .../@22-gpio-14
 *     echo 6-0025 > /sys/bus/i2c/drivers/pca953x/bind
 *
 * NOTE: @25 is left status="ok" in DT so the i2c device is created at boot (its
 * first probe fails with a single harmless NACK line); we then re-attach it.
 * A cleaner future variant would set @25 status="disabled" and instantiate it
 * here with its of_node, matching stock exactly.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/device.h>

/* Match @25 by its compatible + reg, so we don't depend on a raw phandle. */
#define PCA9535_25_COMPATIBLE	"nxp,pca9535"
#define PCA9535_25_REG		0x25

/* -------- keep the old power-control shim symbol for hsm_imager -------- */
/*
 * hsm_imager.c references pca9535c_power_control() (weakly). The expander is
 * now managed here + by gpio-pca953x, and hsm_imager toggles @25's pins via
 * gpiod once it is up, so this remains a successful no-op.
 */
int pca9535c_power_control(int on)
{
	pr_debug("pca9535c_power_control(%d): no-op (expander managed by gpio-pca953x)\n",
		 on);
	return 0;
}
EXPORT_SYMBOL(pca9535c_power_control);

/* Find the pca9535@25 device-tree node (compatible nxp,pca9535, reg 0x25). */
static struct device_node *pca9535c_find_25_node(void)
{
	struct device_node *np = NULL;

	for_each_compatible_node(np, NULL, PCA9535_25_COMPATIBLE) {
		u32 reg;

		if (of_property_read_u32(np, "reg", &reg) == 0 &&
		    reg == PCA9535_25_REG)
			return np;	/* reference held; caller of_node_put()s */
	}
	return NULL;
}

/* Drive one named enable GPIO (property on @25's node, pin on @22) high. */
static int pca9535c_drive_enable(struct device_node *np, const char *prop)
{
	int gpio, ret;

	gpio = of_get_named_gpio(np, prop, 0);
	if (gpio == -EPROBE_DEFER) {
		pr_info("pca9535c: %s not resolvable yet\n", prop);
		return -EPROBE_DEFER;
	}
	if (!gpio_is_valid(gpio)) {
		pr_err("pca9535c: %s invalid (%d)\n", prop, gpio);
		return -EINVAL;
	}
	ret = gpio_request(gpio, prop);
	if (ret && ret != -EBUSY) {	/* -EBUSY: already ours from a prior try */
		pr_err("pca9535c: request %s (gpio %d) failed: %d\n",
		       prop, gpio, ret);
		return ret;
	}
	ret = gpio_direction_output(gpio, 1);
	if (ret) {
		pr_err("pca9535c: drive %s (gpio %d) high failed: %d\n",
		       prop, gpio, ret);
		return ret;
	}
	pr_info("pca9535c: %s (gpio %d) driven high\n", prop, gpio);
	return 0;
}

static int __init pca9535c_scanner_expander_init(void)
{
	struct device_node *np25;
	struct i2c_client *client25;
	int ret;

	np25 = pca9535c_find_25_node();
	if (!np25) {
		pr_err("pca9535c: pca9535@25 node not found\n");
		return 0;
	}

	/* 1) Drive @25's level-shifter + power enables (both on @22) high. */
	ret = pca9535c_drive_enable(np25, "gpio-pca9535c-en");
	if (ret)
		goto out;
	ret = pca9535c_drive_enable(np25, "gpio-level-shift1-en");
	if (ret)
		goto out;

	/* let the rail/level-shifter settle before touching @25 over i2c */
	msleep(10);

	/*
	 * 2) @25's first (subsys_initcall) probe failed with a NACK because the
	 *    enables were low. Its i2c device still exists, unbound. Re-attach
	 *    it so gpio-pca953x probes it again - now it answers and registers
	 *    its gpiochip.
	 */
	client25 = of_find_i2c_device_by_node(np25);
	if (!client25) {
		pr_err("pca9535c: @25 i2c device not found (is @25 status=ok?)\n");
		goto out;
	}

	if (client25->dev.driver) {
		/* somehow already bound - nothing to do */
		pr_info("pca9535c: @25 already bound\n");
		put_device(&client25->dev);
		goto out;
	}

	ret = device_attach(&client25->dev);
	if (ret == 1)
		pr_info("pca9535c: @25 attached (scanner expander up)\n");
	else if (ret == 0)
		pr_err("pca9535c: @25 re-attach found no driver\n");
	else
		pr_err("pca9535c: @25 re-attach failed: %d\n", ret);

	put_device(&client25->dev);
out:
	of_node_put(np25);
	return 0;
}

/*
 * late_initcall: runs after gpio-pca953x's subsys_initcall, so @22 (which owns
 * the enable GPIOs) is registered and of_get_named_gpio() on @25's enable
 * properties resolves.
 */
late_initcall(pca9535c_scanner_expander_init);

MODULE_DESCRIPTION("Casio DT-X400 PCA9535 scanner-expander bring-up");
MODULE_LICENSE("GPL v2");
