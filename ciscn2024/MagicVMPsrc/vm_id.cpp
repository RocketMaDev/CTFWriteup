struct vm_id {
    int always1;
    int padding;
    long op;
    long opertype;
    long num1;
    long num2;
};

// vm_id::check_addr(unsigned long, vm&)

bool __thiscall vm_id::check_addr(vm_id *this,ulong addr,vm *pvm)

{
    return addr <= pvm->datasize - 8U;
}


// vm_id::check_regs(unsigned long, vm&)

bool __thiscall vm_id::check_regs(vm_id *this,byte cmp)

{
    undefined7 in_register_00000031;
    
    return CONCAT71(in_register_00000031,cmp) < 4;
}

// vm_id::run(vm&)

int __thiscall vm_id::run(vm_id *this,vm *pvm)

{
    bool bVar1;
    int iVar2;
    byte *pc;
    undefined7 extraout_var;
    undefined7 extraout_var_00;
    undefined7 extraout_var_01;
    int ret;
    long *val3;
    byte op;
    byte reg1;
    byte opertype;
    byte reg;
    long *val2;
    
    pc = (byte *)(pvm->pc + pvm->code);
    op = *pc;
    ret = 1;
    if (((char)op < 1) || (8 < (char)op)) {
        if (((char)op < 9) || (10 < (char)op)) {
            if ((op == 0) || (op == 0xb)) {
                this->op = (long)(char)op;
                this->opertype = 0;
                this->num1 = 0;
                this->num2 = 0;
            }
            else {
                this->op = -1;
            }
        }
        else {
            opertype = pc[1];
            ret = 2;
            this->opertype = (long)(char)opertype;
            if ((opertype & 3) == 2) {
                ret = 3;
                reg1 = pc[2];
                bVar1 = check_regs(this,reg1);
                if ((int)CONCAT71(extraout_var_01,bVar1) == 0) {
                    this->op = -1;
                }
                else {
                    this->op = (long)(char)op;
                    this->num1 = (long)(char)reg1;
                    this->num2 = 0;
                }
            }
            else {
                this->op = -1;
            }
            if ((pvm->sp & 7U) != 0) {
                this->op = -1;
            }
                    // push
            if (op == 9) {
                if (((ulong)pvm->stacksize <= (ulong)pvm->sp) || ((ulong)pvm->sp < 8)) {
                    this->op = -1;
                }
            }
            else {
                    // pop
                if (pvm->stacksize - 8U < (ulong)pvm->sp) {
                    this->op = -1;
                }
            }
        }
    }
    else {
                    // 0<=op<=8
        val2 = (long *)(pc + 2);
        opertype = pc[1];
        this->opertype = (long)(char)opertype;
        if ((opertype & 3) == 2) {
            ret = 3;
            val3 = (long *)(pc + 3);
            reg = *(byte *)val2;
            bVar1 = check_regs(this,reg);
            if ((int)CONCAT71(extraout_var,bVar1) == 0) {
                this->op = -1;
            }
            else {
                this->op = (long)(char)op;
                this->num1 = (long)(char)reg;
            }
        }
        else if ((opertype & 3) == 3) {
            ret = 3;
            val3 = (long *)(pc + 3);
            reg = *(byte *)val2;
            iVar2 = check_addr(this,pvm->regs[(int)(char)reg],pvm);
            if (iVar2 == 0) {
                this->op = -1;
            }
            else {
                this->op = (long)(char)op;
                this->num1 = (long)(char)reg;
                ret = 3;
            }
        }
        else {
            this->op = -1;
            ret = 2;
            val3 = val2;
        }
        if (this->op != -1) {
            opertype = (char)opertype >> 2 & 3;
            if (opertype == 3) {
                ret += 1;
                opertype = *(byte *)val3;
                iVar2 = check_addr(this,pvm->regs[(int)(char)opertype],pvm);
                if (iVar2 == 0) {
                    this->op = -1;
                }
                else {
                    this->num2 = (long)(char)opertype;
                }
            }
            else {
                if (opertype < 4) {
                    if (opertype == 1) {
                        ret += 8;
                        this->num2 = *val3;
                        goto retlabel;
                    }
                    if (opertype == 2) {
                        ret += 1;
                        opertype = *(byte *)val3;
                        bVar1 = check_regs(this,opertype);
                        if ((int)CONCAT71(extraout_var_00,bVar1) == 0) {
                            this->op = -1;
                        }
                        else {
                            this->num2 = (long)(char)opertype;
                        }
                        goto retlabel;
                    }
                }
                this->op = -1;
            }
        }
    }
retlabel:
    this->always1 = 1;
    return ret;
}

