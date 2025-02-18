# CN-ASS-1
## Usage

Change directory to CN-ASS-1
```
$ sudo bin/python code/first.py
```
In another terminal start tcpreplay
```
$ sudo tcpreplay -i lo --pps 100 <pcap file>
```
When tcpreplay completed than press Ctrl+C on sniffing terminal and wait for result

#### Note - It count extra 4 pkts because pyshark LiveCapture() send broadcast signal to connect

### Note  - first.py is not optimize, It uses lot of memory and may terminated by os if memory is not sufficient. Screnshot of this attached for reference.

## use second.py code .....

