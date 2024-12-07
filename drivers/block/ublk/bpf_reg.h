// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef UBLK_INT_BPF_REG_HEADER
#define UBLK_INT_BPF_REG_HEADER

#include <linux/types.h>

struct bpf_prog_consumer;
struct bpf_prog_provider;

typedef int (*bpf_prog_attach_t)(struct bpf_prog_consumer *consumer,
				 struct bpf_prog_provider *provider);
typedef void (*bpf_prog_detach_t)(struct bpf_prog_consumer *consumer,
				  bool unreg);

struct bpf_prog_consumer_ops {
	bpf_prog_attach_t		attach_fn;
	bpf_prog_detach_t		detach_fn;
};

struct bpf_prog_consumer {
	const struct bpf_prog_consumer_ops	*ops;
	unsigned int				prog_id;
	struct list_head			node;
	struct bpf_prog_provider		*provider;
};

struct bpf_prog_provider {
	struct list_head	list;
};

static inline void bpf_prog_provider_init(struct bpf_prog_provider *provider)
{
	INIT_LIST_HEAD(&provider->list);
}

static inline bool bpf_prog_provider_is_empty(
		struct bpf_prog_provider *provider)
{
	return list_empty(&provider->list);
}

static inline int bpf_prog_consumer_attach(struct bpf_prog_consumer *consumer,
					   struct bpf_prog_provider *provider)
{
	const struct bpf_prog_consumer_ops *ops = consumer->ops;

	if (!ops || !ops->attach_fn)
		return -EINVAL;

	if (ops->attach_fn) {
		int ret = ops->attach_fn(consumer, provider);

		if (ret)
			return ret;
	}
	consumer->provider = provider;
	list_add(&consumer->node, &provider->list);
	return 0;
}

static inline void bpf_prog_consumer_detach(struct bpf_prog_consumer *consumer,
					    bool unreg)
{
	const struct bpf_prog_consumer_ops *ops = consumer->ops;

	if (!consumer->provider)
		return;

	if (!list_empty(&consumer->node)) {
		if (ops && ops->detach_fn)
			ops->detach_fn(consumer, unreg);
		list_del_init(&consumer->node);
		consumer->provider = NULL;
	}
}

#endif
