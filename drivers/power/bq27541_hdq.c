/*
 * TI bq27541 fuel gauge over bit-banged HDQ, for the Casio DT-X400
 *
 * Clean-room driver for the gauge inside the DT-X400 battery pack,
 * reached via TI's single-wire HDQ protocol on a TLMM gpio (open
 * drain with external pull-up). Protocol and register map per TI's
 * public bq27541 documentation; device integration (devicetree
 * binding "qcom,msm8916-fuel-hdq", supply name "bq27542_bms"
 * consumed by the smb135x charger via qcom,bms-psy-name) matches
 * the stock kernel, whose GPL source Casio never published.
 *
 * Licensed under the GNU General Public License v2.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

/* HDQ wire timing (us), per TI HDQ specification */
#define HDQ_BREAK_LOW		250	/* tB: break, >= 190 */
#define HDQ_BREAK_RECOVERY	50	/* tBR: >= 40 */
#define HDQ_BIT_TOTAL		210	/* tCYCH: >= 190 */
#define HDQ_WRITE_1_LOW		2	/* tHW1: 0.5..50 */
#define HDQ_WRITE_0_LOW		100	/* tHW0: 86..145 */
#define HDQ_READ_STROBE		8	/* tHR: 0.5..50 */
#define HDQ_READ_SAMPLE		20	/* sample after release */
#define HDQ_RESPONSE_SLOT	250	/* slave read slot, >= tCYCD */

#define HDQ_ADDR_WRITE		0x80	/* MSB of address byte = write */

/* bq27541 standard commands */
#define BQ27541_REG_TEMP	0x06	/* 0.1 K */
#define BQ27541_REG_VOLT	0x08	/* mV */
#define BQ27541_REG_FLAGS	0x0a
#define BQ27541_REG_AI		0x14	/* avg current, signed mA */
#define BQ27541_REG_CC		0x2a	/* cycle count */
#define BQ27541_REG_SOC		0x2c	/* % */

#define BQ27541_FLAG_DSG	BIT(0)
#define BQ27541_FLAG_FC		BIT(9)

#define POLL_INTERVAL_FAST	(5 * HZ)
#define POLL_INTERVAL_NORM	(10 * HZ)

#define POLL_INTERVAL_CONFIRM	(2 * HZ)

struct bq27541 {
	struct device		*dev;
	int			gpio;
	struct mutex		lock;
	struct delayed_work	work;
	struct power_supply	psy;

	/* cache */
	int			soc;
	int			volt_mv;
	int			curr_ma;
	int			temp_dk;	/* 0.1 K */
	int			flags;
	bool			online;

	int			fail_count;
	bool			drop_pending;
};

/* --- HDQ bit-bang primitives; timing critical, irqs off per bit --- */
static void hdq_write_bit(struct bq27541 *bq, int bit)
{
	unsigned long irqflags;

	local_irq_save(irqflags);
	gpio_direction_output(bq->gpio, 0);
	udelay(bit ? HDQ_WRITE_1_LOW : HDQ_WRITE_0_LOW);
	gpio_direction_input(bq->gpio);
	local_irq_restore(irqflags);
	udelay(HDQ_BIT_TOTAL - (bit ? HDQ_WRITE_1_LOW : HDQ_WRITE_0_LOW));
}

/* poll for a gpio level, irqs assumed off; returns 0 or -ETIMEDOUT */
static int hdq_wait_level(struct bq27541 *bq, int level, int timeout_us)
{
	while (timeout_us-- > 0) {
		if (!!gpio_get_value(bq->gpio) == level)
			return 0;
		udelay(1);
	}
	return -ETIMEDOUT;
}

#define HDQ_SAMPLE_DELAY	65	/* us after falling edge: high=1, low=0 */
#define HDQ_FIRST_EDGE_TIMEOUT	400	/* covers tRSPS (190..320us) */
#define HDQ_EDGE_TIMEOUT	300
#define HDQ_RISE_TIMEOUT	200

static int hdq_read_bit(struct bq27541 *bq, bool first)
{
	unsigned long irqflags;
	int val, err;

	local_irq_save(irqflags);
	err = hdq_wait_level(bq, 0, first ? HDQ_FIRST_EDGE_TIMEOUT
					  : HDQ_EDGE_TIMEOUT);
	if (err) {
		local_irq_restore(irqflags);
		return err;
	}
	udelay(HDQ_SAMPLE_DELAY);
	val = !!gpio_get_value(bq->gpio);	/* back high already = 1 */
	err = hdq_wait_level(bq, 1, HDQ_RISE_TIMEOUT);
	local_irq_restore(irqflags);
	return err ? err : val;
}

static void hdq_break(struct bq27541 *bq)
{
	gpio_direction_output(bq->gpio, 0);
	udelay(HDQ_BREAK_LOW);
	gpio_direction_input(bq->gpio);
	udelay(HDQ_BREAK_RECOVERY);
}

static void hdq_write_byte(struct bq27541 *bq, u8 val)
{
	int i;

	for (i = 0; i < 8; i++)		/* LSB first */
		hdq_write_bit(bq, (val >> i) & 1);
}

static int hdq_read_byte(struct bq27541 *bq)
{
	int val = 0, bit, i;

	for (i = 0; i < 8; i++) {		/* LSB first */
		bit = hdq_read_bit(bq, i == 0);
		if (bit < 0)
			return bit;
		val |= bit << i;
	}
	return val;
}

static int bq27541_read_word(struct bq27541 *bq, u8 reg)
{
	int lo, hi;

	mutex_lock(&bq->lock);
	hdq_break(bq);
	hdq_write_byte(bq, reg);
	lo = hdq_read_byte(bq);
	if (lo >= 0) {
		hdq_break(bq);
		hdq_write_byte(bq, reg + 1);
		hi = hdq_read_byte(bq);
	} else {
		hi = lo;
	}
	mutex_unlock(&bq->lock);

	return (lo < 0 || hi < 0) ? -ETIMEDOUT : ((hi << 8) | lo);
}

/* --- polling and power_supply glue --- */
static void bq27541_poll(struct work_struct *work)
{
	struct bq27541 *bq = container_of(work, struct bq27541, work.work);
	int soc, volt, temp, flags, curr;
	unsigned long delay;

	soc   = bq27541_read_word(bq, BQ27541_REG_SOC);
	volt  = bq27541_read_word(bq, BQ27541_REG_VOLT);
	temp  = bq27541_read_word(bq, BQ27541_REG_TEMP);
	flags = bq27541_read_word(bq, BQ27541_REG_FLAGS);
	curr  = (s16)bq27541_read_word(bq, BQ27541_REG_AI);

	/* transport errors: keep last-good, count towards absence */
	if (soc < 0 || volt < 0 || temp < 0 || flags < 0) {
		if (++bq->fail_count > 5 && bq->online) {
			dev_warn(bq->dev, "gauge not responding\n");
			bq->online = false;
			power_supply_changed(&bq->psy);
		}
		goto resched;
	}
	bq->fail_count = 0;

	/* plausibility gate: physically impossible snapshots */
	if (soc > 100 || volt < 2500 || volt > 4500 ||
	    temp < 2231 || temp > 3431) {		/* -50..70 C */
		dev_warn_ratelimited(bq->dev,
			"implausible read rejected: soc=%d mv=%d dk=%d\n",
			soc, volt, temp);
		goto resched;
	}

	/* contradiction gate: near-empty SOC on a healthy voltage */
	if (soc < 10 && volt > 3800) {
		dev_warn_ratelimited(bq->dev,
			"contradictory read rejected: soc=%d at %dmV\n",
			soc, volt);
		goto resched;
	}

	/* large sudden SOC drop: confirm on a fast follow-up poll */
	if (bq->online && bq->soc - soc > 10 && !bq->drop_pending) {
		bq->drop_pending = true;
		dev_warn(bq->dev, "SOC drop %d->%d, awaiting confirmation\n",
			 bq->soc, soc);
		schedule_delayed_work(&bq->work, POLL_INTERVAL_CONFIRM);
		return;
	}
	bq->drop_pending = false;

	if (!bq->online || soc != bq->soc || flags != bq->flags) {
		bq->online = true;
		bq->soc     = soc;
		bq->volt_mv = volt;
		bq->temp_dk = temp;
		bq->flags   = flags;
		bq->curr_ma = curr;
		power_supply_changed(&bq->psy);
	} else {
		bq->volt_mv = volt;
		bq->temp_dk = temp;
		bq->curr_ma = curr;
	}

resched:
	delay = (bq->online && bq->soc < 20) ? POLL_INTERVAL_FAST
					     : POLL_INTERVAL_NORM;
	schedule_delayed_work(&bq->work, delay);
}

static enum power_supply_property bq27541_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_CYCLE_COUNT,
};

static int bq27541_get_property(struct power_supply *psy,
				enum power_supply_property prop,
				union power_supply_propval *val)
{
	struct bq27541 *bq = container_of(psy, struct bq27541, psy);

	switch (prop) {
	case POWER_SUPPLY_PROP_STATUS:
		if (!bq->online)
			val->intval = POWER_SUPPLY_STATUS_UNKNOWN;
		else if (bq->flags & BQ27541_FLAG_FC)
			val->intval = POWER_SUPPLY_STATUS_FULL;
		else if (bq->flags & BQ27541_FLAG_DSG)
			val->intval = POWER_SUPPLY_STATUS_DISCHARGING;
		else
			val->intval = POWER_SUPPLY_STATUS_CHARGING;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = bq->online;
		break;
	case POWER_SUPPLY_PROP_TECHNOLOGY:
		val->intval = POWER_SUPPLY_TECHNOLOGY_LION;
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = POWER_SUPPLY_HEALTH_GOOD;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = bq->volt_mv * 1000;
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		val->intval = bq->curr_ma * 1000;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = bq->soc;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		/* 0.1 K -> 0.1 degC */
		val->intval = bq->temp_dk - 2731;
		break;
	case POWER_SUPPLY_PROP_CYCLE_COUNT:
		val->intval = bq27541_read_word(bq, BQ27541_REG_CC);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int bq27541_probe(struct platform_device *pdev)
{
	struct bq27541 *bq;
	int error;

	bq = devm_kzalloc(&pdev->dev, sizeof(*bq), GFP_KERNEL);
	if (!bq)
		return -ENOMEM;

	bq->dev = &pdev->dev;
	bq->gpio = of_get_named_gpio(pdev->dev.of_node, "qcom,hdq-gpio", 0);
	if (!gpio_is_valid(bq->gpio)) {
		dev_err(&pdev->dev, "hdq gpio not specified\n");
		return -ENODEV;
	}

	error = devm_gpio_request(&pdev->dev, bq->gpio, "bq27541-hdq");
	if (error) {
		dev_err(&pdev->dev, "failed to request hdq gpio: %d\n", error);
		return error;
	}
	gpio_direction_input(bq->gpio);

	mutex_init(&bq->lock);
	INIT_DELAYED_WORK(&bq->work, bq27541_poll);

	/* defaults until first successful read */
	bq->soc = 50;
	bq->temp_dk = 2731;

	bq->psy.name		= "bq27542_bms";
	bq->psy.type		= POWER_SUPPLY_TYPE_BMS;
	bq->psy.properties	= bq27541_props;
	bq->psy.num_properties	= ARRAY_SIZE(bq27541_props);
	bq->psy.get_property	= bq27541_get_property;

	error = power_supply_register(&pdev->dev, &bq->psy);
	if (error) {
		dev_err(&pdev->dev, "psy registration failed: %d\n", error);
		return error;
	}

	platform_set_drvdata(pdev, bq);
	schedule_delayed_work(&bq->work, HZ);

	dev_info(&pdev->dev, "bq27541 fuel gauge (HDQ) registered\n");
	return 0;
}

static const struct of_device_id bq27541_of_match[] = {
	{ .compatible = "qcom,msm8916-fuel-hdq" },
	{ }
};
MODULE_DEVICE_TABLE(of, bq27541_of_match);

static struct platform_driver bq27541_driver = {
	.driver = {
		.name		= "bq27541-hdq",
		.owner		= THIS_MODULE,
		.of_match_table	= bq27541_of_match,
	},
	.probe = bq27541_probe,
};
module_platform_driver(bq27541_driver);

MODULE_DESCRIPTION("TI bq27541 fuel gauge over bit-banged HDQ");
MODULE_LICENSE("GPL v2");
