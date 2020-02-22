import angr

project = angr.Project('./r100')

@project.hook(0x400849)
def print_flag(state):
    print("F:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
