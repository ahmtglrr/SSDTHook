#include <ntddk.h>


//SSDT Yapýsý
typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, *PSSDT;

extern PSSDT KeServiceDescriptorTable; //SSDT Pointeri

#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1)); //Servis numarasýný almak için kullanýlýr

typedef NTSTATUS(*pNtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS(*pNtLoadDriver)(PUNICODE_STRING);


NTSTATUS ZwQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG); //Proses ismini almak için kullanýlýr

ULONG OrigNtTerminateProcess, OrigNtLoadDriver, SSDTAddress[2]; //NTterminateproses ve NtloadDriver fonksiyonlarýnýn Orjinal adreslerini depolamak için tanýmladýk.

pNtTerminateProcess fnNtTerminateProcess;
pNtLoadDriver fnNtLoadDriver;



NTSTATUS HookNtTerminateProcess(HANDLE hProcess, NTSTATUS ExitStatus)
{
	PUNICODE_STRING ProcessName;

	if (hProcess != NULL && hProcess != (HANDLE)-1)
	{
		ProcessName = ExAllocatePool(NonPagedPool, 4096); //Proses ismi için hafýzada yer ayrýlýyor.

														  
		//Proses ismini alýyoruz.
		if (NT_SUCCESS(ZwQueryInformationProcess(hProcess, 27, ProcessName, 4096, NULL)))
		{
			if (wcsstr(ProcessName->Buffer, L"calc.exe") != NULL) //Proses ismimizi burada kontrol ediyoruz.
			{
				DbgPrint("calc.exe prosesi sonlandýrýlmaya çalýþýlýyor.Eriþim Reddedildi..\n", PsGetCurrentProcessId()); //Proses ismi calc.exe ise eriþimi engelle
				ExFreePool(ProcessName); //Ayýrdýðýmýz belleði býrakýyoruz.
				return STATUS_ACCESS_DENIED;
			}
		}

		ExFreePool(ProcessName);
	}

	return fnNtTerminateProcess(hProcess, ExitStatus);
}

//Sürücüyü  DebugView'de görüntülemek için.
NTSTATUS HookNtLoadDriver(PUNICODE_STRING DriverName)
{
	DbgPrint("NtLoadDriver bu proses tarafýndan çaðrýldý %d. Driver ismi: %ws\n", PsGetCurrentProcessId(), DriverName->Buffer);
	return fnNtLoadDriver(DriverName);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{	//Fonksiyonlarýn servis numaralarýný alýyoruz.
	ULONG ServiceNumber[2];

	ServiceNumber[0] = GetServiceNumber(ZwTerminateProcess);
	ServiceNumber[1] = GetServiceNumber(ZwLoadDriver);
	//wp bitini burada read-only moddan çýkarmak için bozuyoruz.
	__asm
	{
		mov eax, cr0
		and eax, not 0x10000
		mov cr0, eax
	}
	SSDTAddress[0] = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber[0] * 4;//ZwTerminateProses fonksiyonun adresini alýp SSDTAddress dizisinin içinde saklýyoruz.
	SSDTAddress[1] = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber[1] * 4;//ZwLoadDriver fonksiyonun adresini alýp SSDTAddress dizisinin içinde saklýyoruz.
	OrigNtTerminateProcess = *(PULONG)SSDTAddress[0]; //Orjinal adresleri depoluyoruz.
	OrigNtLoadDriver = *(PULONG)SSDTAddress[1];

	fnNtTerminateProcess = (pNtTerminateProcess)OrigNtTerminateProcess;
	fnNtLoadDriver = (pNtLoadDriver)OrigNtLoadDriver;

	//Orjinal adreslerin yerlerini ayný prototipte tanýmladýðýmýz fonksiyonlar ile deðiþtiriyoruz.
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
	DbgPrint("SSDT hook sürücüsü yüklendi.\n");
	return STATUS_SUCCESS;
}