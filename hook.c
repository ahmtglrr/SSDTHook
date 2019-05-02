#include <ntddk.h>


//SSDT Yap�s�
typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, *PSSDT;

extern PSSDT KeServiceDescriptorTable; //SSDT Pointeri

#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1)); //Servis numaras�n� almak i�in kullan�l�r

typedef NTSTATUS(*pNtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS(*pNtLoadDriver)(PUNICODE_STRING);


NTSTATUS ZwQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG); //Proses ismini almak i�in kullan�l�r

ULONG OrigNtTerminateProcess, OrigNtLoadDriver, SSDTAddress[2]; //NTterminateproses ve NtloadDriver fonksiyonlar�n�n Orjinal adreslerini depolamak i�in tan�mlad�k.

pNtTerminateProcess fnNtTerminateProcess;
pNtLoadDriver fnNtLoadDriver;



NTSTATUS HookNtTerminateProcess(HANDLE hProcess, NTSTATUS ExitStatus)
{
	PUNICODE_STRING ProcessName;

	if (hProcess != NULL && hProcess != (HANDLE)-1)
	{
		ProcessName = ExAllocatePool(NonPagedPool, 4096); //Proses ismi i�in haf�zada yer ayr�l�yor.

														  
		//Proses ismini al�yoruz.
		if (NT_SUCCESS(ZwQueryInformationProcess(hProcess, 27, ProcessName, 4096, NULL)))
		{
			if (wcsstr(ProcessName->Buffer, L"calc.exe") != NULL) //Proses ismimizi burada kontrol ediyoruz.
			{
				DbgPrint("calc.exe prosesi sonland�r�lmaya �al���l�yor.Eri�im Reddedildi..\n", PsGetCurrentProcessId()); //Proses ismi calc.exe ise eri�imi engelle
				ExFreePool(ProcessName); //Ay�rd���m�z belle�i b�rak�yoruz.
				return STATUS_ACCESS_DENIED;
			}
		}

		ExFreePool(ProcessName);
	}

	return fnNtTerminateProcess(hProcess, ExitStatus);
}

//S�r�c�y�  DebugView'de g�r�nt�lemek i�in.
NTSTATUS HookNtLoadDriver(PUNICODE_STRING DriverName)
{
	DbgPrint("NtLoadDriver bu proses taraf�ndan �a�r�ld� %d. Driver ismi: %ws\n", PsGetCurrentProcessId(), DriverName->Buffer);
	return fnNtLoadDriver(DriverName);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{	//Fonksiyonlar�n servis numaralar�n� al�yoruz.
	ULONG ServiceNumber[2];

	ServiceNumber[0] = GetServiceNumber(ZwTerminateProcess);
	ServiceNumber[1] = GetServiceNumber(ZwLoadDriver);
	//wp bitini burada read-only moddan ��karmak i�in bozuyoruz.
	__asm
	{
		mov eax, cr0
		and eax, not 0x10000
		mov cr0, eax
	}
	SSDTAddress[0] = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber[0] * 4;//ZwTerminateProses fonksiyonun adresini al�p SSDTAddress dizisinin i�inde sakl�yoruz.
	SSDTAddress[1] = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber[1] * 4;//ZwLoadDriver fonksiyonun adresini al�p SSDTAddress dizisinin i�inde sakl�yoruz.
	OrigNtTerminateProcess = *(PULONG)SSDTAddress[0]; //Orjinal adresleri depoluyoruz.
	OrigNtLoadDriver = *(PULONG)SSDTAddress[1];

	fnNtTerminateProcess = (pNtTerminateProcess)OrigNtTerminateProcess;
	fnNtLoadDriver = (pNtLoadDriver)OrigNtLoadDriver;

	//Orjinal adreslerin yerlerini ayn� prototipte tan�mlad���m�z fonksiyonlar ile de�i�tiriyoruz.
	*(PULONG)SSDTAddress[0] = (ULONG)HookNtTerminateProcess;
	*(PULONG)SSDTAddress[1] = (ULONG)HookNtLoadDriver;

	//wp bitini tekrar read-only durumuna getiriyoruz.
	__asm
	{
		mov eax, cr0
		or eax, 0x10000
		mov cr0, eax
	}
	DbgPrint("NtTerminateProcess address: %#x\n", OrigNtTerminateProcess);
	DbgPrint("NtLoadDriver address: %#x\n", OrigNtLoadDriver);
	DbgPrint("NtTerminateProcess Hook.\n");
	DbgPrint("NtLoadDriver Hook..\n");
	DbgPrint("SSDT hook s�r�c�s� y�klendi.\n");
	return STATUS_SUCCESS;
}