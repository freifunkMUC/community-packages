#include <linux/kernel.h>
#include <linux/skbuff.h>
#ifndef skb_set_transport_header_careful
static inline bool skb_set_transport_header_careful(struct sk_buff *skb, const int offset)
{
	unsigned int off = skb->data - skb->head + offset;
	if (unlikely(off > 0xffff))
		return false;
	skb->transport_header = (typeof(skb->transport_header))off;
	return true;
}
#endif
