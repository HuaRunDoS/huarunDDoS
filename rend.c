/* --------网络空间反射请求接收 (支持配置文件读取端口)-----
 * 用于接收网络空间的反射请求并存储，端口从配置文件读取
 * 用于研究
 */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

#define MAX_PACKET_SIZE 65535
#define MISS_SIZE 8

volatile int found_srvs = 0;      
int RPROT = 0;                    
FILE *fp;


static char *trim(char *s) {
  char *end;
  while (isspace((unsigned char)*s)) s++;
  if (*s == 0) return s;
  end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) end--;
  *(end + 1) = '\0';
  return s;
}


static void load_config(const char *path) {
  FILE *cfg = fopen(path, "r");
  if (!cfg) {
      perror("打开配置文件失败");
      exit(1);
  }
  char line[256];
  while (fgets(line, sizeof(line), cfg)) {
    char *s = trim(line);
    if (*s == '\0' || *s == '#' || *s == ';') continue;
    char *eq = strchr(s, '=');
    if (!eq) continue;
    *eq = '\0';
    char *key = trim(s);
    char *val = trim(eq + 1);
    if (strcmp(key, "port") == 0) {
      RPROT = atoi(val);
      break;
    }
  }
  fclose(cfg);
  if (RPROT <= 0 || RPROT > 65535) {
    fprintf(stderr, "无效的端口配置: %d\n", RPROT);
    exit(1);
  }
  printf("[*] 反射端口: %d\n", RPROT);
}


void sighandler(int sig) {
  if (fp) fclose(fp);
  printf("\n程序已终止\n");
  exit(0);
}


typedef struct packet {
  char data[MAX_PACKET_SIZE];
  ssize_t len;
  struct sockaddr_in addr;
  struct packet *next;
} packet_t;


typedef struct {
  packet_t *head;
  packet_t *tail;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
} packet_queue_t;

static packet_queue_t pkt_queue = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

void enqueue(packet_queue_t *q, packet_t *pkt) {
  pthread_mutex_lock(&q->mutex);
  pkt->next = NULL;
  if (!q->tail) q->head = pkt;
  else q->tail->next = pkt;
  q->tail = pkt;
  pthread_cond_signal(&q->cond);
  pthread_mutex_unlock(&q->mutex);
}

packet_t *dequeue(packet_queue_t *q) {
  pthread_mutex_lock(&q->mutex);
  while (!q->head) pthread_cond_wait(&q->cond, &q->mutex);
  packet_t *pkt = q->head;
  q->head = pkt->next;
  if (!q->head) q->tail = NULL;
  pthread_mutex_unlock(&q->mutex);
  return pkt;
}


void *recievethread(void *arg) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock < 0) { perror("socket"); exit(1); }
  int one = 1;
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
  char buffer[MAX_PACKET_SIZE];
  struct sockaddr_in sin;
  socklen_t addr_len = sizeof(sin);
  while (1) {
    ssize_t data_size = recvfrom(sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr*)&sin, &addr_len);
    if (data_size <= 0) continue;
    packet_t *pkt = malloc(sizeof(*pkt));
    if (!pkt) { perror("malloc"); continue; }
    memcpy(pkt->data, buffer, data_size);
    pkt->len = data_size;
    pkt->addr = sin;
    enqueue(&pkt_queue, pkt);
  }
  close(sock);
  return NULL;
}


void *process_thread(void *arg) {
  while (1) {
    packet_t *pkt = dequeue(&pkt_queue);
    struct iphdr *iph = (struct iphdr*)pkt->data;
    if (iph->protocol != IPPROTO_UDP) { free(pkt); continue; }
    struct udphdr *udph = (struct udphdr*)(pkt->data + iph->ihl*4);
    if (ntohs(udph->source) != RPROT) { free(pkt); continue; }
    int payload_start = iph->ihl*4 + sizeof(*udph);
    int payload_len = pkt->len - payload_start;
    if (payload_len < MISS_SIZE) { free(pkt); continue; }
    fprintf(fp, "%s %d\n", inet_ntoa(pkt->addr.sin_addr), payload_len);
    fflush(fp);
    found_srvs++;
    free(pkt);
  }
  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <配置文件> <结果文件>\n", argv[0]);
    return 1;
  }
  signal(SIGINT, sighandler);
  load_config(argv[1]);
  fp = fopen(argv[2], "w");
  if (!fp) { perror("打开结果文件失败"); return 1; }
  pthread_t t1, t2;
  pthread_create(&t1, NULL, recievethread, NULL);
  pthread_create(&t2, NULL, process_thread, NULL);
  sleep(1);
  while (1) {
    printf("\r已找到: %d", found_srvs);
    fflush(stdout);
    sleep(1);
  }
  return 0;
}
