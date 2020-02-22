import angr
import claripy
p=angr.Project('./very_success',auto_load_libs=False)
Ent=0x040105F
l=40
s=p.factory.blank_state(addr=Ent)
flag=claripy.BVS("flag",l*8)
s.memory.store(0x0402159,flag)
s.mem[s.regs.esp+8:].dword=l#len
s.mem[s.regs.esp+4:].dword=0x0402159#addr
s.mem[s.regs.esp:].dword=0x04010e4#

sim=p.factory.simgr(s)
sim.explore(find=0x040106B,avoid=0x0401072)
assert(len(sim.found)==1)
fd=sim.found[0]
print fd.solver.eval(flag,cast_to=bytes)
