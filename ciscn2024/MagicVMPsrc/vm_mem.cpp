struct memunit {
    long *addr;
    long val;
};

struct vm_mem {
    int domem;
    int iter;
    memunit memunits[2];
};

// vm_mem::run(vm&)

void __thiscall vm_mem::run(vm_mem *this)

{
    int i;
    
    if (this->domem != 0) {
        for (i = 0; i < this->iter; i += 1) {
            *this->memunits[i].addr = this->memunits[i].val;
        }
    }
    return;
}


// vm_mem::set_input(vm&)

void __thiscall vm_mem::set_input(vm_mem *this,vm *param_1)

{
    long *plVar1;
    int iVar2;
    vm_alu *aluptr;
    
    aluptr = param_1->alu;
    iVar2 = aluptr->iter;
    plVar1 = aluptr->addr0;
    this->domem = aluptr->domem;
    this->iter = iVar2;
    this->memunits[0].addr = plVar1;
    plVar1 = aluptr->addr1;
    this->memunits[0].val = aluptr->val0;
    this->memunits[1].addr = plVar1;
    this->memunits[1].val = aluptr->val1;
    return;
}

