#include <Windows.h>
#include <iostream>

int main() {
	//��ȡdll����
	HANDLE dll = CreateFileA("C:\\Users\\macfy\\source\\repos\\srdi\\x64\\Debug\\testdll.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD64 dllSize = GetFileSize(dll, NULL);
	LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
	DWORD outSize = 0;
	ReadFile(dll, dllBytes, dllSize, &outSize, NULL);

	//����dll
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS peHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);

	LPVOID imageBuffer = VirtualAlloc(NULL,peHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memcpy(imageBuffer, dllBytes, peHeaders->OptionalHeader.SizeOfHeaders);

	//��DLL�ڲ��ָ��Ƶ��·����DLL�ռ�
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(peHeaders);

	for (size_t i = 0; i < peHeaders->FileHeader.NumberOfSections; i++)
	{
		/*LPVOID sectionDestination = (LPVOID)((DWORD_PTR)imageBuffer + (DWORD_PTR)section->VirtualAddress);
		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
		std::memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
		section++;*/


		std::memcpy(
			(PVOID)((LPBYTE)imageBuffer + section[i].VirtualAddress), 
			(PVOID)((LPBYTE)dllBytes + section[i].PointerToRawData), 
			section[i].SizeOfRawData);

	}
	
	//�ض�λ
    
	DWORD delta = (DWORD)((LPBYTE)imageBuffer - peHeaders->OptionalHeader.ImageBase);


	return 0;
}