#include <windows.h>

#include <iostream>

int main(void)

{

    //加载我们的dll

    HINSTANCE hinst = ::LoadLibrary(L"C:\\Users\\macfy\\source\\repos\\srdi\\x64\\Debug\\testdll.dll");

    if (NULL != hinst)

    {

        printf("ok");

    }

    return 0;

}