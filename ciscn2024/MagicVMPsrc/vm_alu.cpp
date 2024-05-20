struct vm_alu {
    long always1;
    long ins; // instruction
    long opertype; // 00: forbid, 01: imm, 10: reg, 11: addr
    long num1;
    long num2;
    int domem; // write mem?
    int iter;  // enable addr1?
    long *addr0;
    long val0;
    long *addr1;
    long val1;
};

// vm_alu::set_input(vm&)

void __thiscall vm_alu::set_input(vm_alu *this,vm *pvm)

{
    vm_id *pvVar1;
    long op;
    
    pvVar1 = pvm->id;
    op = pvVar1->op;
    this->always1 = *(long *)pvVar1;
    this->ins = op;
    op = pvVar1->num1;
    this->opertype = pvVar1->opertype;
    this->num1 = op;
    this->num2 = pvVar1->num2;
    return;
}


// vm_alu::run(vm&)

undefined8 __thiscall vm_alu::run(vm_alu *this,vm *pvm)

{
    uint uVar1;
    undefined8 uVar2;
    ulong op;
    
    if (*(int *)&this->always1 == 0) {
        return 1;
    }
    if ((this->ins == 0) || (8 < (ulong)this->ins)) {
        op = this->ins;
        if (op == 0xb) {
            this->domem = 0;
            return 1;
        }
        if (op < 0xc) {
                    // pop
            if (op == 10) {
                this->iter = 2;
                this->addr0 = pvm->regs + this->num1;
                this->val0 = *(long *)(pvm->sp + pvm->stack);
                this->addr1 = (long)&pvm->sp;
                this->val1 = pvm->sp + 8;
                goto domem;
            }
            if (op < 0xb) {
                if (op == 0) {
                    this->domem = 0;
                    return 0;
                }
                    // push
                if (op == 9) {
                    this->iter = 2;
                    this->addr0 = (long *)(pvm->sp + pvm->stack + -8);
                    this->val0 = pvm->regs[this->num1];
                    this->addr1 = (long)&pvm->sp;
                    this->val1 = pvm->sp + -8;
                    goto domem;
                }
            }
        }
        uVar2 = 0xffffffff;
    }
    else {
                    // 00:forbid. 01:imm, 10:reg, 11:addr
        uVar1 = (uint)((ulong)this->opertype >> 2) & 3;
        if (uVar1 == 3) {
            this->num2 = *(long *)(pvm->regs[this->num2] + pvm->data);
        }
        else {
            if (3 < uVar1) {
                return 0xffffffff;
            }
            if (uVar1 != 1) {
                if (uVar1 != 2) {
                    return 0xffffffff;
                }
                this->num2 = pvm->regs[this->num2];
            }
        }
        uVar1 = (uint)this->opertype & 3;
        if (uVar1 == 2) {
            this->iter = 1;
            this->addr0 = pvm->regs + this->num1;
            this->num1 = pvm->regs[this->num1];
        }
        else {
            if (uVar1 != 3) {
                return 0xffffffff;
            }
            if (((uint)this->opertype & 0xc) == 0xc) {
                return 0xffffffff;
            }
            this->iter = 1;
            this->addr0 = (long *)(pvm->regs[this->num1] + pvm->data);
            this->num1 = *(long *)(pvm->regs[this->num1] + pvm->data);
        }
        switch(this->ins) {
        case 1:
            this->val0 = this->num1 + this->num2;
            break;
        case 2:
            this->val0 = this->num1 - this->num2;
            break;
        case 3:
            this->val0 = this->num1 << ((byte)this->num2 & 0x3f);
            break;
        case 4:
            this->val0 = (ulong)this->num1 >> ((byte)this->num2 & 0x3f);
            break;
        case 5:
            this->val0 = this->num2;
            break;
        case 6:
            this->val0 = this->num1 & this->num2;
            break;
        case 7:
            this->val0 = this->num1 | this->num2;
            break;
        case 8:
            this->val0 = this->num1 ^ this->num2;
        }
domem:
        this->domem = 1;
        uVar2 = 1;
    }
    return uVar2;
}

