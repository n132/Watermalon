# DES
The supermarket bought a new printer last night. I hacked into their computer and captured the USB traffic on it. Could you help me steal the secret?

Flag format: flag{0-9a-z_} (Convert uppercase to lowercase)
# Start
* wireshark 打开发现是一些USB数据包,双击length找到内涵数据较为丰富的包.
# 分离包内信息
## BAR
首先最明显的是这部分.
```s
BAR:348:439:2:96
BAR:292:535:56:2
BAR:300:495:48:2
BAR:260:447:2:88
BAR:204:447:56:2
BAR:176:447:2:96
BAR:116:455:2:82
BAR:120:479:56:2
BAR:44:535:48:2
BAR:92:455:2:80
BAR:20:455:72:2
BAR:21:455:2:40
BAR:21:495:24:2
BAR:45:479:2:16
BAR:36:479:16:2
BAR:284:391:40:2
BAR:324:343:2:48
BAR:324:287:2:32
BAR:276:287:48:2
BAR:52:311:48:2
BAR:284:239:48:2
BAR:308:183:2:56
BAR:148:239:48:2
BAR:196:191:2:48
BAR:148:191:48:2
BAR:68:191:48:2
BAR:76:151:40:2
BAR:76:119:2:32
BAR:76:55:2:32
BAR:76:55:48:2
BAR:112:535:64:2
BAR:320:343:16:2
BAR:320:319:16:2
BAR:336:319:2:24
BAR:56:120:24:2
BAR:56:87:24:2
BAR:56:88:2:32
BAR:224:247:32:2
BAR:256:215:2:32
BAR:224:215:32:2
BAR:224:184:2:32
BAR:224:191:32:2
BAR:272:311:2:56
BAR:216:367:56:2
BAR:216:319:2:48
BAR:240:318:2:49
BAR:184:351:2:16
BAR:168:351:16:2
BAR:168:311:2:40
BAR:152:351:16:2
BAR:152:351:2:16
```
咕果一下(其实是很久)发现这是`TSC`打印机用的一种叫做`TSPL`的标签语言
于是就去找在线解释器。。。但是找了1一个小时没找到。。。

然后去找文档。。。[文档][1]
阅读了一下其中关于`BAR`的部分发现也不是那么难于是写了脚本画图
```python
'''
#init 

'''

def bar(x,y,w,h):
for i in range(1000):
for k in range(1000):
if i>=y and i <=y+h and k>=x and k<=x+w :
data[i][k]=1

data=[]
for x in range(1000):
data.append([])
for y in range(1000):
data[x].append(0)
fp=open("./op",'r')
ops=fp.read().split('\n')
fp.close()
for x in ops:
tmp=x.split(":")
bar(int(tmp[1]),int(tmp[2]),int(tmp[3]),int(tmp[4]))
#f=open("./map.txt",'w')
final=""
idx=0

from PIL import Image
#file = open('flag.txt')  
#for i in range(0, x):
#    for j in range(0, y):
#        line = file.readline()  


xx=0
yy=0

im = Image.new("RGB", (1000, 1000))   

for x in data:
for y in x:
if y ==0:
im.putpixel((xx,yy),(255,255,255))
yy+=1
elif y==1:
im.putpixel((xx,yy), (0,0,0)) 
yy+=1
if yy==1000:
yy=0
xx+=1
#raw_input()

im.save('flag.jpg')

#f.write(final)
#f.close()
```
发现有点短上交了一下发现不对主办发告诉我说还没做完
于是我开始分析其他部分的信息

# BITMAP

发现还有两条比较明显的BITMAP信息
```s
BITMAP 138,75,26,48,1,
BITMAP 130,579,29,32,1,
```
于是寻找了一下文档中关于BITMAP的信息
```s
BITMAP
Description
This command draws bitmap images(as opposed to BMP graphic files).
Syntax
BITMAP X,Y, width, height, mode, bitmap data...
Parameter
X
Y width height mode
bitmap data
Example
Description
Specifies the x-coordinate Specifies the y-coordinate Image width(in bytes) Image height(in dots) Graphic modes listed below 0:OVERWRITE
1:OR
2:XOR Bitmap data
```
依照规则写了个画图脚本
```python
map2=['ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','c7','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','fe','38','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','fd','ff','7f','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','f9','ff','3f','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','f9','ff','3f','ff','ff','ff','ff','ff','ff','9f','fe','fb','ff','c7','ff','ff','ff','e1','ff','f8','ff','ff','ff','fc','3f','ff','ff','ff','ff','f9','ff','3f','f8','ff','ff','ff','ff','ff','0f','fe','fb','ff','39','ff','00','7f','9c','7f','e7','2f','ff','ff','f3','c3','fc','07','ff','ff','f8','7e','78','46','3f','80','3f','f0','1f','0f','fe','7b','fe','fe','ff','f7','ff','3f','3f','9f','8f','ff','ff','ef','f3','ff','bf','ff','ff','fc','01','fa','3f','9f','fb','ff','fe','7f','9f','fe','71','fc','fe','7f','f7','ff','7f','9f','9f','cf','ff','ff','ef','fb','ff','bf','ff','ff','ff','c0','7e','7f','9f','fb','ff','fe','7f','ff','fc','71','f9','ff','3f','f7','fe','ff','9f','3f','cf','ff','ff','ef','fb','ff','bf','ff','ff','ff','fe','7e','7f','8f','fb','ff','fe','7f','ff','fd','75','f9','ff','3f','f7','ff','ff','cf','3f','cf','ff','ff','e7','ff','ff','bf','ff','ff','ff','fe','7e','7f','9f','fb','ff','fe','7f','ff','fd','35','f9','ff','3f','f7','ff','ff','cf','3f','cf','ff','ff','e3','ff','ff','bf','ff','ff','ff','80','fe','7f','9f','fb','ff','fe','7f','ff','fd','2c','f9','ff','3f','f7','ff','ff','cf','3f','cf','ff','ff','f0','7f','ff','bf','ff','ff','ff','7c','fe','7f','3f','fb','ff','fe','7f','ff','fb','2c','f9','ff','3f','f7','fe','00','0f','3f','cf','ff','ff','fc','1f','ff','bf','ff','ff','fe','7e','7e','7c','7f','fb','ff','fe','7f','ff','fb','ac','f9','ff','3f','f7','fe','7f','cf','3f','cf','ff','ff','ff','87','ff','bf','ff','ff','fe','7e','7e','03','ff','fb','ff','fe','7f','ff','fb','9e','f9','ff','3f','f7','fe','7f','cf','3f','cf','ff','ff','ff','e7','ff','bf','ff','ff','fe','fe','7e','7f','ff','fb','ff','fe','7f','ff','fb','9e','79','ff','3f','f7','fe','7f','9f','3f','cf','ff','ff','ef','f3','ff','bf','ff','ff','fe','fe','7e','7f','9f','fb','ff','fe','7f','ff','f7','9e','7c','fe','7f','f7','ff','3f','9f','9f','8f','ff','ff','ef','f3','ff','bf','ff','ff','fe','7e','7f','7f','1f','fb','ff','fe','7f','1f','f7','9e','7e','fc','ff','f7','ff','3f','3f','9f','0f','ff','ff','e7','f7','ff','bf','ff','ff','f2','7e','ff','3f','3f','fb','ff','fe','7f','0f','e3','8e','3f','39','ff','f7','ff','ce','7f','c0','4f','ff','ff','e1','cf','ff','9f','ff','ff','f0','19','ff','9e','7f','fb','ff','fe','7f','1f','ff','ff','ff','c7','ff','f7','ff','f1','ff','fb','cf','ff','ff','ee','3f','ff','87','ff','ff','fb','e7','ff','e1','ff','fb','ff','e0','0f','ff','ff','ff','ff','ff','ff','f7','ff','ff','ff','ff','cf','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','fb','ff','fe','7f','ff','ff','ff','ff','ff','ff','f7','ff','ff','ff','ff','cf','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','fb','ff','fe','7f','ff','ff','ff','ff','ff','ff','f7','ff','ff','ff','ff','cf','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','fb','ff','fe','7f','ff','ff','ff','ff','ff','ff','f7','ff','ff','ff','ff','cf','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','fb','fe','7e','7f','ff','ff','ff','ff','ff','ff','f7','ff','ff','ff','ff','cf','ff','ff','ff','ff','ff','3f','ff','ff','ff','ff','ff','ff','ff','fb','fe','7e','ff','ff','ff','ff','ff','ff','ff','f7','ff','ff','ff','ff','cf','ff','ff','ff','ff','ff','1f','ff','ff','ff','ff','ff','ff','ff','fb','fe','7c','ff','ff','ff','ff','ff','ff','ff','f0','3f','ff','ff','ff','c3','ff','ff','ff','ff','ff','1f','ff','ff','ff','ff','ff','ff','ff','f8','1f','03','ff','ff','ff','ff','ff','ff','ff','f3','ff','ff','ff','ff','cf','ff','ff','ff','ff','ff','bf','ff','ff','ff','ff','ff','ff','ff','f9','ff','ff','ff']
map1=['ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','00','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','c3','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','e7','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','e7','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','e7','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','e7','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','e7','ff','e3','ff','fe','1f','ff','ff','ff','ff','f8','07','c0','3c','60','3f','c0','7c','07','e0','00','7f','7f','f0','1f','80','67','ff','00','7f','f8','03','fc','07','c0','3f','ff','1f','f1','f0','4f','8f','f1','ff','1f','ff','1f','ff','3f','fc','ff','1f','27','fc','7f','1f','f3','e1','ff','1f','f9','ff','ff','1f','f1','fc','1f','cf','f8','ff','1f','ff','1f','ff','3f','fe','fe','3f','87','f8','ff','9f','ef','f8','ff','1f','f9','ff','ff','8f','f1','fc','3f','c7','fc','ff','1f','ff','1f','ff','1f','fe','fc','7f','c7','f9','ff','8f','df','fc','7f','1f','f9','ff','ff','8f','f1','fc','7f','e3','fc','7f','1f','ff','1f','ff','1f','fe','fc','ff','e7','f1','ff','8f','9f','fc','3f','1f','f9','ff','ff','c7','f1','fc','7f','e3','fe','3f','1f','ff','1f','ff','0f','fe','f8','ff','e7','f1','ff','0f','bf','fe','3f','1f','f9','ff','ff','c7','f1','fc','7f','e3','fe','3f','1f','ff','1f','ff','0f','fe','f8','ff','e7','e1','ff','8f','3f','fe','3f','1f','f9','ff','ff','e3','f1','fc','7f','e3','ff','1f','1f','ff','1f','ff','47','fe','f8','ff','e7','e3','ff','9f','7f','fe','1f','1f','f9','ff','ff','e3','f1','fc','7f','f3','ff','8e','1f','ff','1f','ff','47','fe','f9','ff','e7','e3','ff','ff','ff','ff','1f','1f','f9','ff','ff','f1','f1','fc','7f','f3','ff','8c','1f','ff','1f','ff','63','fe','f9','ff','e7','f1','ff','ff','ff','ff','1f','1f','f9','ff','ff','f1','f1','fc','7f','f3','ff','c1','1f','ff','1f','ff','63','fe','f9','ff','e7','f1','ff','ff','ff','ff','1f','1f','f9','ff','ff','f1','f1','fc','7f','e3','ff','e3','1f','ff','1f','ff','71','fe','f9','ff','e7','f1','ff','ff','ff','ff','1f','1f','f9','ff','ff','f8','f1','fc','7f','e3','ff','e7','1f','ff','1f','ff','71','fe','f8','ff','e7','f8','ff','ff','ff','ff','0f','1f','f9','ff','ff','f8','f1','fc','7f','e3','ff','cf','1f','ff','1f','ff','78','fe','f8','ff','e7','fc','ff','ff','ff','ff','0f','1f','f9','ff','ff','fc','61','fc','7f','e7','ff','9f','1f','ff','1f','ff','78','fe','f8','ff','c7','fe','3f','ff','ff','ff','0f','1f','f9','ff','ff','fc','41','fc','7f','c7','ff','3f','1f','ff','1f','ff','7c','7e','fc','ff','c7','ff','83','ff','ff','ff','0f','9f','f1','ff','ff','fe','11','fc','3f','8f','ff','7f','1f','ff','1f','ff','7c','7e','fc','7f','a7','ff','87','ff','ff','ff','0f','9f','e9','ff','ff','fe','31','fc','1f','1f','fe','7f','1f','ff','1f','ff','7e','3e','fe','3e','67','fe','3f','ff','ff','ff','1f','8f','99','ff','ff','ff','31','fc','40','3f','e0','1f','1f','ff','1f','ff','7e','3e','ff','80','e0','fc','7f','ff','ff','ff','1f','c0','39','ff','ff','fe','71','fc','79','ff','ff','ff','1f','ff','1f','ff','7f','1e','ff','f3','ef','f8','ff','ff','ff','ff','1f','f0','f9','ff','ff','fe','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','0e','ff','ff','ff','f8','ff','ff','ff','ff','1f','ff','f9','ff','ff','fc','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','8e','ff','ff','ff','f8','ff','ff','ff','fe','1f','ff','f9','ff','ff','f9','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','86','ff','ff','ff','f8','ff','9f','7f','fe','3f','ff','f9','ff','ff','fb','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','c6','ff','ff','ff','f8','ff','0f','3f','fe','3f','ff','f9','ff','ff','f7','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','c2','ff','ff','ff','f8','ff','8f','bf','fc','7f','ff','f9','ff','ff','e7','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','e2','ff','ff','ff','f8','ff','8f','9f','fc','7f','ff','f9','ff','ff','cf','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','f0','ff','ff','ff','fc','ff','9f','9f','f8','ff','ff','f9','ff','ff','8f','f1','fc','7f','ff','ff','ff','1f','ff','1f','ff','7f','f0','ff','ff','ff','fc','7f','9f','8f','f1','ff','ff','f9','ff','ff','0f','f0','fc','3f','ff','ff','ff','1f','ff','0f','fe','7f','f8','ff','ff','ff','fe','1e','7f','83','e3','ff','ff','f8','ff','fc','03','c0','3c','0f','ff','ff','ff','03','e0','00','78','0f','f8','3f','ff','ff','ff','80','ff','f8','0f','ff','ff','f8','3f','ff','ff','ff','fd','ff','ff','ff','ff','3f','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','fb','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff','ff']
idx=0
res=[]
for x in range(29*8):
res.append([])
for y in range(32*8):
res[x].append(0)
r=""
for x in range(32):
for y in range(29):
tmp=int("0x"+map2[idx],16)
tmp=bin(tmp)[2:]
r+=tmp.rjust(8,'0')
idx+=1
#r+="\n"
idx=0
from PIL import Image
im = Image.new("RGB", (32, 29*8))   
for x in range(32):
for y in range(29*8):
if r[idx]=='1':
im.putpixel((x,y),(255,255,255))
elif r[idx]=='0':
im.putpixel((x,y),(0,0,0))
idx+=1
im.save('map2.jpg')
```
得到了剩余的flag。

[1]: ./programming-manual-for-ht300.pdf


