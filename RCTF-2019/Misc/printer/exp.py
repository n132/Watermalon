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

