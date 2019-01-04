import requests
import re
import cbc
url='https://www.blockchain.com/zh/btc/block-height/{}'
def cat_hash(idx):
    res=requests.get(url=url.format(str(idx)))
    data= res.content
    patten=r'<td>Merkle Root</td>[.\n]                <td>[0-9a-zA-Z///"]{64}'
    res=re.findall(patten,data)[0][-64:]
    return res
def store(low):
    low*=10000
    high=low+10000
    hashs=open("./{}-{}".format(str(low),str(high)),'w')
    for x in range(low,high):
        print x
        hashs.write(cat_hash(x)+"\n")
    hashs.close()
if __name__ == "__main__":
    store(7)