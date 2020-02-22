import angr
import claripy
p=angr.Project("./issue")
n=claripy.BVS("n",8)
s=p.factory.entry_state(add_options={"SYMBOLIC_WRITE_ADDRESSES"})
s.memory.store(0x804a021,n)
sim=p.factory.simgr(s)
sim.explore(find=0x80484DB,avoid=0x80484ED)
print sim.found[0].solver.eval(n)
