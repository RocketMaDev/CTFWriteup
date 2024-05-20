
undefined8 main(void)

{
    basic_ostream *this;
    
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
    this = std::operator<<((basic_ostream *)std::cout,"plz input your vm-code");
    std::basic_ostream<>::operator<<((basic_ostream<> *)this,std::endl<>);
    read(STDIN_FILENO,(void *)my_vm.code,0x2000);
    vm::run(&my_vm);
    return 0;
}

