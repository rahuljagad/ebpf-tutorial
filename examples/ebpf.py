#!/usr/bin/python3
from bcc import BPF
from time import sleep

"""
Tutorial following the program implemented in the YouTube vide
https://www.youtube.com/watch?v=lrSExTfS-iQ&t=12s
"""

#### EBPF Program (that runs in Kernel space) #######
program = """
// ============================================= 

BPF_HASH(clones);

int hello_world(void *ctx) {
  u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  u64 counter = 0;
  u64 *p;

  //lookup the value and increment the value by 1.
  p = clones.lookup(&uid);  
  if (p != 0) {
    counter = *p;
  } 
  counter++;
  clones.update(&uid, &counter);
  
  return 0;
}

// ============================================= 
"""

#### User-Space program.
b = BPF(text=program)
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello_world")


while True:
  sleep(2)
  s = ""
  if len(b["clones"].items()):
    for key,value in b["clones"].items():
      s += "ID: {}: {}\t".format(key.value, value.value)
    print(s)
  else:
    print("No entries yet..")