# 现网真实物理流量抓包教程 (PCAP Capture Tutorial)

如果你目前身处网安学院的本科生实验室，你完全可以利用实验室的局域网环境，捕获一段真实的物理网络流量进行测试，从而完成此项目在“真实生产环境”下全链路闭环的验证体验。

抓包主要有两种常见方式：**Wireshark (提供图形界面，适合新手)** 和 **tcpdump (命令行神器，适合极客/服务器环境)**。这两种工具抓取出来的文件格式统一为 `.pcap`。

---

## 方法一：使用 Wireshark 界面抓包 (推荐新手⭐)

Wireshark 是网安学生的必备神器，操作非常直观。

### 1. 启动与选择网卡
* 打开 Wireshark 软件。
* 在主界面的列表中，寻找有波浪线（代表有流量活动）的网卡。通常：
  * **Mac / Linux**：一般为 `en0` 或 `eth0` 或 `wlan0` (无线)。
  * **Windows**：可能是 `WLAN`、`以太网` 或 `Ethernet`。
* 双击那个有流量波动的网卡，Wireshark 将立刻开始疯狂滚动捕捉当前的流量数据。

### 2. 模拟真实的网络行为
为了让抓到的包有分析价值，你可以同时打开浏览器：
* 访问几个网站（如各大门户网站、视频网站等），产生正常的 TCP/HTTPS 流量。
* 也可以在命令行使用 `ping 8.8.8.8` 来产生 ICMP 数据包。
* 甚至可以在实验室网络内互相进行一次简单的端口扫描（例如使用 nmap，**请确保这在实验室规定允许范围内**）。

### 3. 停止并保存 (保存为 PCAP)
1. 点击左上角的 **红色正方形按钮 (Stop capturing packets)** 停止抓包。
2. 点击菜单栏 **“文件 (File)” -> “另存为 (Save As...)”**。
3. **关键步骤**：在保存类型的下拉菜单中，选择 **`Wireshark/tcpdump/... - pcap`** 格式！(注意：不要选默认的新版 pcapng，我们要选最兼容的 `pcap`)。
4. 命名为 `my_capture.pcap` 并保存到项目的 `data/` 目录中。

---

## 方法二：使用 tcpdump 命令行抓包 (极客向💻)

如果你的 Mac 或 Linux 系统已经预装了 `tcpdump`，你可以直接在网安实验室的终端内“一键完成”：

### 1. 查看可用网卡
打开终端，输入：
```bash
sudo tcpdump -D
```
找到你当前使用的网卡名称，比如 `en0`。

### 2. 执行抓包命令
输入以下命令抓取 1000 个数据包，或者设定抓取时间（这里我们抓取目标网卡的流量并写入文件）：
```bash
# 抓取 en0 网卡上的数据，并不解析域名(-n)，详细输出，保存到 my_capture.pcap
sudo tcpdump -i en0 -n -w my_capture.pcap
```
*此时终端会“挂起”并开始收包。你可以同样做一些上网或网络探测的行为。*
按下 `Ctrl + C` 可以随时强制停止抓包。

### 3. 移动文件
抓完以后，将文件移动到我们的项目中：
```bash
mv my_capture.pcap /Users/zhangxinglang/Desktop/ProgramDesign/data/
```

---

## 第三步：导入系统流程打通

拥有了自己的 `my_capture.pcap` 后，配合我们独创的 `pcap_to_csv.py` 和我们的主程序系统，这套“屠龙技”就可以连招了：

### 打通流程连招：
回到我们项目的根目录。

**1. 将 PCAP 转化提纯为系统专属 CSV：**
```bash
python py/pcap_to_csv.py data/my_capture.pcap data/my_real_data.csv
```
*(成功后，会看到 "Success! Converted XXX IP packets into session CSV format." 的提示)*

**2. 喂给我们的底座高性能分析器：**
```bash
# 执行异常流量排序，找出可疑发包节点
./app --input data/my_real_data.csv sort-oneway --threshold 0.8
```

或 **3. 启动“苹果风”前端去欣赏你自己抓取的拓扑！**
```bash
python py/server.py
```
*(在前端的“上传并解析 CSV”位置，或者直接在加载数据那里填写 `data/my_real_data.csv` 就可以在可视化界面看到你刚才抓到的网络通信关系网了！)*
