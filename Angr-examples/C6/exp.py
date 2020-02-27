import angr
p=angr.Project('./UEP')
s=p.factory.blank_state(addr=0x4005BD)
flag=[s.solver.BVS("flag_%d"%x,8) for x in range(0x43)]
for x in range(0x43):
	s.mem[0x6042C0+x].byte=flag[x]
for x in flag:
	s.add_constraints(s.solver.And(x >= 32,x<=127))
sim=p.factory.simgr(s)
sim.active[0].options.add(angr.options.LAZY_SOLVES)
import time
t=time.time()
sim.explore(find=0x400724,avoid=0x400850)
print time.time()-t
print sim.found[0].solver.eval(sim.found[0].memory.load(0x6042C0,8*0x43),cast_to=bytes).strip('\0')

