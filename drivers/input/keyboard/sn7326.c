/*
 * Si-En SN7326 I2C matrix keypad controller driver
 *
 * Clean-room implementation for the Casio DT-X400 (LineageOS port).
 * Chip protocol determined from the device's stock GPL kernel binary,
 * for which no source was ever published:
 *   - key event register 0x10: bits[5:0] position (row * 8 + col),
 *     bit 6 press/release, bit 7 more events pending
 *   - config register 0x08, initialized to 0x3c
 *   - reset via GPIO pulse: high, 10ms, low, 50ms, high
 *
 * Copyright (C) 2026
 * Licensed under the GNU General Public License v2.
 */

#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/input.h>
#include <linux/input/matrix_keypad.h>
#include <linux/gpio/consumer.h>
#include <linux/delay.h>
#include <linux/of.h>

#define SN7326_REG_KEY		0x10
#define SN7326_KEY_MASK		0x3f
#define SN7326_KEY_DOWN		BIT(6)
#define SN7326_MORE_EVENTS	BIT(7)

#define SN7326_REG_CFG		0x08
#define SN7326_CFG_INIT		0x3c

#define SN7326_MAX_KEYS		64

struct sn7326 {
	struct i2c_client	*client;
	struct input_dev	*input;
	struct gpio_desc	*reset_gpios;
	unsigned short		keymap[SN7326_MAX_KEYS];
};

static irqreturn_t sn7326_irq(int irq, void *dev_id)
{
	struct sn7326 *kp = dev_id;
	int val;

	do {
		val = i2c_smbus_read_byte_data(kp->client, SN7326_REG_KEY);
		if (val < 0) {
			dev_err(&kp->client->dev,
				"key register read failed: %d\n", val);
			break;
		}

		input_event(kp->input, EV_MSC, MSC_SCAN,
			    val & SN7326_KEY_MASK);
		input_report_key(kp->input,
				 kp->keymap[val & SN7326_KEY_MASK],
				 !!(val & SN7326_KEY_DOWN));
		input_sync(kp->input);
	} while (val & SN7326_MORE_EVENTS);

	return IRQ_HANDLED;
}

static int sn7326_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct sn7326 *kp;
	struct input_dev *input;
	unsigned int rows = 0, cols = 0;
	int error;

	if (!i2c_check_functionality(client->adapter,
				     I2C_FUNC_SMBUS_BYTE_DATA)) {
		dev_err(&client->dev, "SMBus byte data not supported\n");
		return -EIO;
	}

	kp = devm_kzalloc(&client->dev, sizeof(*kp), GFP_KERNEL);
	if (!kp)
		return -ENOMEM;

	kp->client = client;

	error = matrix_keypad_parse_of_params(&client->dev, &rows, &cols);
	if (error)
		return error;

	if (rows * cols > SN7326_MAX_KEYS) {
		dev_err(&client->dev, "matrix too large\n");
		return -EINVAL;
	}

	kp->reset_gpios = devm_gpiod_get_optional(&client->dev,
						  "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(kp->reset_gpios)) {
		error = PTR_ERR(kp->reset_gpios);
		if (error != -EPROBE_DEFER)
			dev_err(&client->dev,
				"failed to acquire reset gpio: %d\n", error);
		return error;
	}

	if (kp->reset_gpios) {
		msleep(10);
		gpiod_set_value_cansleep(kp->reset_gpios, 0);
		msleep(50);
		gpiod_set_value_cansleep(kp->reset_gpios, 1);
	}

	error = i2c_smbus_read_byte_data(client, SN7326_REG_KEY);
	if (error < 0) {
		dev_err(&client->dev, "chip not responding: %d\n", error);
		return -ENODEV;
	}

	input = devm_input_allocate_device(&client->dev);
	if (!input)
		return -ENOMEM;

	kp->input = input;
	input->name = client->name;
	input->id.bustype = BUS_I2C;

	error = matrix_keypad_build_keymap(NULL, NULL, rows, cols,
					   kp->keymap, input);
	if (error) {
		dev_err(&client->dev, "failed to build keymap: %d\n", error);
		return error;
	}

	input_set_capability(input, EV_MSC, MSC_SCAN);

	error = i2c_smbus_write_byte_data(client, SN7326_REG_CFG,
					  SN7326_CFG_INIT);
	if (error < 0) {
		dev_err(&client->dev, "config write failed: %d\n", error);
		return error;
	}

	error = devm_request_threaded_irq(&client->dev, client->irq,
					  NULL, sn7326_irq,
					  IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
					  client->name, kp);
	if (error) {
		dev_err(&client->dev, "failed to request irq: %d\n", error);
		return error;
	}

	error = input_register_device(input);
	if (error) {
		dev_err(&client->dev,
			"failed to register input device: %d\n", error);
		return error;
	}

	return 0;
}

static const struct of_device_id sn7326_of_match[] = {
	{ .compatible = "sn7326,matrix-keypad" },
	{ }
};
MODULE_DEVICE_TABLE(of, sn7326_of_match);

static const struct i2c_device_id sn7326_ids[] = {
	{ "keypad", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, sn7326_ids);

static struct i2c_driver sn7326_driver = {
	.driver = {
		.name		= "sn7326",
		.owner		= THIS_MODULE,
		.of_match_table	= sn7326_of_match,
	},
	.probe		= sn7326_probe,
	.id_table	= sn7326_ids,
};
module_i2c_driver(sn7326_driver);

MODULE_DESCRIPTION("Si-En SN7326 I2C matrix keypad driver");
MODULE_LICENSE("GPL v2");
