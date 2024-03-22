// test_asm.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include "aa.h"

//extern "C" int _stdcall MY_TEST();
EXTERN_C int _stdcall MY_TEST();

int main()
{
    std::cout << "Hello World!\n";

    //int a = Int_3();
    int b = MY_TEST();
    int c = add();

    return 0;
}

