struct vm {
    long regs[4];
    long sp;
    long pc;
    long code;
    long data;
    long stack;
    long codesize;
    long datasize;
    long stacksize;
    vm_id *id;
    vm_alu *alu;
    vm_mem *mem;
};

// vm::vm()

void __thiscall vm::vm(vm *this)

{
    void *map0x6000;
    vm_id *idptr;
    vm_alu *aluptr;
    vm_mem *memptr;
    long lVar1;
    
    map0x6000 = mmap(NULL,0x6000,PROT_EXEC|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS.,-1,0);
    this->code = (long)map0x6000;
    this->data = this->code + 0x2000;
    this->stack = this->data + 0x3000;
    this->datasize = 0x3000;
    this->codesize = 0x2000;
    this->stacksize = 0x1000;
    idptr = (vm_id *)operator_new(0x28);
    idptr->always1 = 0;
    idptr->op = 0;
    idptr->opertype = 0;
    idptr->num1 = 0;
    idptr->num2 = 0;
    this->id = idptr;
    aluptr = (vm_alu *)operator_new(0x50);
    aluptr->always1 = 0;
    aluptr->ins = 0;
    aluptr->opertype = 0;
    aluptr->num1 = 0;
    aluptr->num2 = 0;
    aluptr->domem = 0;
    aluptr->iter = 0;
    aluptr->addr0 = NULL;
    aluptr->val0 = 0;
    aluptr->addr1 = 0;
    aluptr->val1 = 0;
    this->alu = aluptr;
    memptr = (vm_mem *)operator_new(0x28);
    memptr->domem = 0;
    memptr->iter = 0;
    lVar1 = 0;
    while( true ) {
        memptr->memunits[lVar1].addr = NULL;
        memptr->memunits[lVar1].val = 0;
        if (lVar1 == 1) break;
        lVar1 += 1;
    }
    this->mem = memptr;
    return;
}


// vm::run()

undefined8 __thiscall vm::run(vm *this)

{
    int count;
    basic_ostream *this_00;
    
    do {
        vm_alu::set_input(this->alu,this);
        vm_mem::set_input(this->mem,this);
        count = vm_id::run(this->id,this);
        this->pc = this->pc + (long)count;
        count = vm_alu::run(this->alu,this);
        vm_mem::run(this->mem);
        if (count == 0) {
            return 0;
        }
    } while (count != -1);
    this_00 = std::operator<<((basic_ostream *)std::cout,"SOME STHING WRONG!!");
    std::basic_ostream<>::operator<<((basic_ostream<> *)this_00,std::endl<>);
                    // WARNING: Subroutine does not return
    exit(EXIT_SUCCESS);
}

