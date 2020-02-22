# zore
import angr
p=angr.Project("./crackme0x00a")
s=p.factory.simgr()
s.explore(find = lambda aim: "Co" in aim.posix.dumps(1))
print s.found[0].posix.dumps(0)
#output:g00dJ0B!
