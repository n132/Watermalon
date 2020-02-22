import angr
import time
import re
import claripy
p=angr.Project("./baby-re")
flag_buf = [claripy.BVS("flag_%d" % x,32) for x in range(13)]
s=p.factory.blank_state(addr=0x4028E0)
for x in range(13):
	s.memory.store(s.regs.rdi+x*4,flag_buf[x])
sim=p.factory.simulation_manager(s)
sim.active[0].options.add(angr.options.LAZY_SOLVES)
start_time=time.time()
sim.explore(find=0x4028E9, avoid=0x402941)
print sim.found[0].solver.eval(flag_buf[0])
print str(time.time()-start_time)

