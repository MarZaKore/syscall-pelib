﻿// pe_lib.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

extern "C" void test();

int main()
{
    std::cout << "Hello World!\n";

    test();



    return 0;
}

