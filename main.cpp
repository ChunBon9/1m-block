#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <iostream>
#include <string>
#include <set>
#include <ctime>

using namespace std;
set <string> malicious_sites;

typedef struct IP{
	uint8_t v_i;
	uint8_t tos;
	uint16_t t_len;
	uint16_t id;
	uint16_t flag_N_f_off;
	uint8_t ttl;
	uint8_t prot;
	uint16_t hd_chk;
	uint32_t src_adr;
	uint32_t dst_adr;	
}*ip_hdr;

typedef struct TCP{
	int16_t src_port;
	int16_t dst_port;
	int32_t sq_num;
	int32_t ack_num;
	int16_t do_rsv_f;
	int16_t win_size;
	int16_t chk;
	int16_t urg_p; 
}*tcp_hdr;

void usage() {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, int *chk)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		int i;
		char site[1000];
		printf("payload_len=%d\n", ret);
		char method[5][7] = {"GET", "POST", "PUT", "DELETE", "PATCH"};
		if((((ip_hdr)data)->v_i >> 4) == 0x4)	{
			if(((ip_hdr)data)->prot == 0x6)	{
				data = (uint8_t *)data + ((((ip_hdr)data)->v_i & 0x0F) << 2);
				data = (uint8_t *)data + ((ntohs(((tcp_hdr)data)->do_rsv_f) >> 12) << 2);
				
				for(i=0; i<5; i++) {
					if(strncasecmp((const char*)data, method[i], strlen(method[i])) == 0) break;
				}
				
				if(i != 5) {
					for(i=0; i<ret; i++) {
						if(strncmp((const char*)data + i, "Host: ", 6) == 0) break;
					}
					
					int offset = i + 6;
					for(i=offset; i<ret; i++) {
						if(data[i] == '\n') {
							site[i-offset-1] = '\0';
							break;
						}
						site[i-offset] = data[i];
					}
					if(i != ret-i-6) {
						if(malicious_sites.count(string(site))) {
									*chk = 0;
									printf("BLOCKED : %s\n", site);
						}
						else {
							for(i=0; i<strlen(site); i++) {		
								if(site[i]=='.') {
									if(malicious_sites.count(string(site+i+1))) {
										*chk = 0;
										printf("BLOCKED : %s\n", site);
										break;	
									}
								}
							}
						}	
					}
				}
			}
		}
	}
	//fputc('\n', stdout);
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int chk = 1;
	int NF;
	u_int32_t id = print_pkt(nfa, &chk);
	printf("entering callback\n");
	chk ? NF = NF_ACCEPT : NF = NF_DROP; 
	return nfq_set_verdict(qh, id, NF, 0, NULL);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
		return -1;
	}
	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	long start_t, end_t;
	char buf[4096] __attribute__ ((aligned));
	
	start_t = clock();
	FILE *fp = fopen(argv[1], "r");
	char line[1000];
	while(fgets(line, sizeof(line), fp))
	{	
		int i;
		line[strlen(line)-1] = '\0';
		for(i=0; i<strlen(line); i++)
		{
			if(line[i] != ',') continue;
			i++;
			break;
		}
		string site(&line[i]);
		malicious_sites.insert(site);
	}
	fclose(fp);
	end_t = clock();
	printf("CLOCKS PER SEC: %ld\n", CLOCKS_PER_SEC);
	printf("%ldclocks elapsed to load list\n", end_t - start_t);
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			start_t = clock();
			nfq_handle_packet(h, buf, rv);
			end_t = clock();
			printf("%ldclocks elapsed\n\n", end_t - start_t);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
