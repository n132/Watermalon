import angr
import time
import re
import claripy
p=angr.Project("./baby-re",auto_load_libs=False)
flag_buf = [claripy.BVS("flag_%d" % x,32) for x in range(13)]
class do_scanf(angr.SimProcedure):
	def run(self,fmt,ptr):
		self.state.mem[ptr].dword = flag_buf[self.state.globals['idx']]
		self.state.globals['idx']+=1
p.hook_symbol('__isoc99_scanf',do_scanf(),replace=True)
sim=p.factory.simgr()
sim.active[0].globals['idx']=0
sim.active[0].options.add(angr.options.LAZY_SOLVES)
start_time=time.time()
sim.explore(find=0x4028E9, avoid=0x402941)
flag=''
print str(time.time()-start_time)
for x in range(13):
	flag+=chr(sim.found[0].solver.eval(flag_buf[x]))
print flag
