/****************************************************************************

������ init.c

������ ������ � ����������� �������� � ���������� ��������.

������ ���� �������������               17.04.2014

****************************************************************************/


#include <ntddk.h>


//*************************************************************
// ������� � ���������� ����������


#define	SYM_LINK_NAME   L"\\Global??\\Driver"
#define DEVICE_NAME     L"\\Device\\DDriver"


UNICODE_STRING glDeviceName;
UNICODE_STRING glSymLinkName;

LIST_ENTRY glOpenFiles;
PAGED_LOOKASIDE_LIST glPagedList;
char* str_er = "Error!!! NOT FILE!!!";


typedef struct _OpenFileEntry {

	ANSI_STRING fileName;
	UNICODE_STRING fullName;
	LIST_ENTRY link;

} OpenFileEntry;

// ������� ��������� �������
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;        // ������ ������� ��������� �������(��������)
	PULONG Count;           // ������ ��������� ������� ��������
	ULONG Limit;            // ���������� ������� � �������
	PUCHAR Number;          // ������ ���������� ���������� �������(� ������)
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

// �������� ������� NtCreateFile
typedef NTSTATUS(*NT_CREATE_FILE)(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
	);
typedef NTSTATUS(*NT_OPEN_FILE)(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	);

// ����� ������ NtCreateFile � ������� ��������� �������
#define NUMBER_NT_CREATE_FILE   0x25
#define NUMBER_NT_OPEN_FILE		0x74



//*************************************************************
// ��������������� ���������� �������
NTSTATUS HookNtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
	);
NTSTATUS HookNtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	);
//NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
//VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);
//*************************************************************
// ��������������� ���������� �������


DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH DispatchCreate;
__drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH DispatchClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DispatchControl;
__drv_dispatchType(IRP_MJ_READ) DRIVER_DISPATCH DispatchRead;
__drv_dispatchType(IRP_MJ_WRITE) DRIVER_DISPATCH DispatchWrite;
__drv_dispatchType(IRP_MJ_QUERY_INFORMATION) DRIVER_DISPATCH DispatchQueryInformation;
//__drv_dispatchType(IRP_MJ_SET_INFORMATION) DRIVER_DISPATCH DispatchSetInformation;
//NTSTATUS DispatchSetInformation(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS CompleteIrp(PIRP pIrp, NTSTATUS status, ULONG info);


//*************************************************************
// �������� �������
// ���������� ����������

// ����� ������� NtCreateFile
NT_CREATE_FILE glRealNtCreateFile;
NT_OPEN_FILE glRealNtOpenFile;

UNICODE_STRING glProtectedFiles[2];

// ������� ��������� �������
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;


//*************************************************************
// �������� �������


ULONG ClearWP(void) {

	ULONG reg;

	__asm {
		mov eax, cr0
			mov[reg], eax
			and eax, 0xFFFEFFFF
			mov cr0, eax
	}

	return reg;
}


void WriteCR0(ULONG reg) {

	__asm {
		mov eax, [reg]
			mov cr0, eax
	}

}
//void WaitHookUnload(ULONG *p) {
//
//	KEVENT event;
//	LARGE_INTEGER time;
//
//	time.QuadPart = -10000000;
//
//	KeInitializeEvent(&event, SynchronizationEvent, FALSE);
//
//while (*p) {
//	KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &time);
//}
//}
PWCH AnsiToUnicode(char *str) {

	ANSI_STRING ansiStr;
	UNICODE_STRING uniStr;
	USHORT length;

	RtlInitAnsiString(&ansiStr, str);
	length = RtlAnsiStringToUnicodeSize(&ansiStr);
	uniStr.Buffer = (PWCH)ExAllocatePool(PagedPool, length);
	uniStr.MaximumLength = length;
	RtlAnsiStringToUnicodeString(&uniStr, &ansiStr, FALSE);

	return uniStr.Buffer;
}

//void InitProtectedFiles(){
//	//glProtectedFiles = (PUNICODE_STRING)ExAllocatePool(PagedPool, sizeof(UNICODE_STRING) * 2);
//	glProtectedFiles[0] = AnsiToUnicode("test1");
//	glProtectedFiles[1] = AnsiToUnicode("test2");
//}
//
//void FreeProtectedFiles() {
//	RtlFreeUnicodeString(&glProtectedFiles[0]);
//	RtlFreeUnicodeString(&glProtectedFiles[1]);
//}

//
// ������� ������������� ��������.
//
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING RegistryPath) {

	PDEVICE_OBJECT  pDeviceObject;				// ��������� �� ������ ����������
	NTSTATUS		status = STATUS_SUCCESS;	// ������ ���������� �������
	ULONG reg;
	UNICODE_STRING f1;
	char* str;
	char* ptr;
	int len;
	//InitProtectedFiles();
	//DbgPrint("ProtectedFiles: %wZ, %wZ", &glProtectedFiles[0], &glProtectedFiles[1]);
	//DbgPrint("Load driver %wZ", &DriverObject->DriverName);
	//DbgPrint("Registry path %wZ", RegistryPath);




	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	//pDriverObject->MajorFunction [IRP_MJ_CREATE_NAMED_PIPE       ] = 0;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	//pDriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = DispatchQueryInformation;
	//pDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = DispatchSetInformation;

	pDriverObject->DriverUnload = DriverUnload;

	KdPrint(("Load driver %wZ\n", &pDriverObject->DriverName));
	KdPrint(("Registry path %wZ\n", RegistryPath));

	RtlInitUnicodeString(&glDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&glSymLinkName, SYM_LINK_NAME);

	// �������� ����������
	status = IoCreateDevice(pDriverObject,         // ��������� �� ������ ��������
		0,                     // ������ ������� �������������� ������ ����������
		&glDeviceName,         // ��� ����������
		FILE_DEVICE_UNKNOWN,   // ������������� ���� ����������
		0,                     // �������������� ���������� �� ����������
		FALSE,                 // ������������ ��������(��� ��������� ������ ���� FALSE)
		&pDeviceObject);       // ����� ��� ���������� ��������� �� ������ ����������
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// �������������� ����/����� ��� �������� ������/������
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	KdPrint(("Create device %wZ\n", &glDeviceName));

	// �������� ���������� ������
	status = IoCreateSymbolicLink(&glSymLinkName, &glDeviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	KdPrint(("Create symbolic link %wZ\n", &glSymLinkName));

	//str = (char*)ExAllocatePool(NonPagedPool, strlen("\\??\\C:\\") + strlen("boot.ini") + 1);
	//strcat(str, "\\??\\C:\\");
	//KdPrint(("+%s\n", str));
	//strcat(str, "boot.ini");
	//KdPrint(("++%s\n", str));
	//f1.Buffer = AnsiToUnicode(str);
	//KdPrint(("+++%S\n", f1.Buffer));
	/*if(wcsstr(L"\\??\\C:\\boot.ini", L"\\??\\C:\\boot1.ini") != NULL){
		KdPrint(("YES!!!\n"));
	}*/




	// ������� ��������� ������
	ExInitializePagedLookasideList(&glPagedList, NULL, NULL, 0, sizeof(OpenFileEntry), ' LFO', 0);

	InitializeListHead(&glOpenFiles);

	// ���������� ����� ��������� ����������� ������ NtCreateFile
	glRealNtCreateFile = (NT_CREATE_FILE)KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE];
	glRealNtOpenFile = (NT_OPEN_FILE)KeServiceDescriptorTable->Base[NUMBER_NT_OPEN_FILE];
	//glRealNtOpenFile = KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE];
	// ����������� ����� ������ �����������
	//reg = ClearWP();
	KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE] = (ULONG)HookNtCreateFile;
	KeServiceDescriptorTable->Base[NUMBER_NT_OPEN_FILE] = (ULONG)HookNtOpenFile;
	//WriteCR0(reg);

	return status;
}


//--------------------

//
// �������, ���������� ��� �������� ��������.
//
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject) {
	ULONG reg;

	// �������� ���������� ������ � ������� ����������
	IoDeleteSymbolicLink(&glSymLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	// ������� �������� ������ ������
	while (!IsListEmpty(&glOpenFiles)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glOpenFiles);
		OpenFileEntry *entry = CONTAINING_RECORD(pLink, OpenFileEntry, link);
		RtlFreeAnsiString(&entry->fileName);
		RtlFreeUnicodeString(&entry->fullName);

		ExFreeToPagedLookasideList(&glPagedList, entry);
	}

	// ������� ��������� ������
	ExDeletePagedLookasideList(&glPagedList);

	KdPrint(("Driver unload\n"));
	//reg = ClearWP();
	KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE] = (ULONG)glRealNtCreateFile;
	KeServiceDescriptorTable->Base[NUMBER_NT_OPEN_FILE] = (ULONG)glRealNtOpenFile;
	//WriteCR0 (reg);

	//WaitHookUnload(&glHookCounter);
	//FreeProtectedFiles();

	return;
}
//----------------------------------------

// �������-���������� ���������� ������ NtCreateFile
NTSTATUS HookNtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
	)
{
	//FILE_OBJECT *file;
	//NTSTATUS status;
	NTSTATUS retstatus;
	KPROCESSOR_MODE mode;
	//FILE_NAME_INFORMATION *fni;
	//IO_STATUS_BLOCK isb;
	PWCHAR fullFileName;
	//UNICODE_STRING f1;
	PLIST_ENTRY link;
	OpenFileEntry *entry;
	//char* str;
	//int len1;
	//int len2;
	//char* ptr;


	mode = ExGetPreviousMode();
	if (mode == KernelMode)
		mode = 'K';
	else
		mode = 'U';

	retstatus = glRealNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);


	//if (ObjectAttributes->RootDirectory){
	//	fni = (FILE_NAME_INFORMATION*)ExAllocatePool(PagedPool, 0x1000);
	//	if (!fni){

	//	}
	//	else{

	//		status = ZwQueryInformationFile(
	//			ObjectAttributes->RootDirectory,   // ��������� �����
	//			&isb,                              // ����� ��������� IO_STATUS_BLOCK
	//			fni,                               // ����� ��� ���������� ����������
	//			0x1000,                            // ������ ������
	//			FileNameInformation                // ��� ���������� - ��� �����
	//			);
	//		if (NT_SUCCESS(status)){
	//			fni->FileName[(isb.Information - 4) / 2] = 0;

	//			fullFileName = ExAllocatePool(PagedPool, fni->FileNameLength + ObjectAttributes->ObjectName->Length + 2);
	//			wcscpy(fullFileName, fni->FileName);
	//			wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
	//			DbgPrint("%c: %d.%d (%X)\t FullFileName - %S\n", mode, PsGetCurrentProcessId(), PsGetCurrentThreadId(), retstatus, fullFileName);
	//		}
	//		else{
	//			fullFileName = ExAllocatePool(PagedPool, ObjectAttributes->ObjectName->Length + 2);
	//			wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);

	//			DbgPrint("%c: %d.%d (%X)\tFullFileName - %S\n", mode, PsGetCurrentProcessId(), PsGetCurrentThreadId(), retstatus, fullFileName);
	//		}
	//		ExFreePool(fni);
	//	}
	//}
	//else {
	//	fullFileName = ExAllocatePool(PagedPool, ObjectAttributes->ObjectName->Length + 2);
	//	wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);

	//	DbgPrint("%c: %d.%d (%X)\tFullFileName: %S\n", mode, PsGetCurrentProcessId(), PsGetCurrentThreadId(), retstatus, fullFileName);
	//}

	for (link = glOpenFiles.Flink; link != &glOpenFiles; link = link->Flink) {
		entry = CONTAINING_RECORD(link, OpenFileEntry, link);

	//	
	fullFileName = ExAllocatePool(PagedPool, ObjectAttributes->ObjectName->Length + 2);
		wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
		if (wcsstr(_wcslwr(fullFileName), _wcslwr(entry->fullName.Buffer)) != NULL)

			retstatus = STATUS_ACCESS_DENIED;
	//		DbgPrint("+%S\n", _wcslwr(fullFileName));
	//		DbgPrint("++%S\n", _wcslwr(entry->fullName.Buffer));
	//		DbgPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++File secured!");
		}

	//	
	//}

	//ExFreePool(fullFileName);


	return retstatus;
}


//----------------------------------------

//--------------------

//
// ������� ��������� ������� �� �������� ���������� ��������.
//
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS status = STATUS_SUCCESS;   // ������ ���������� �������� �����/������
	PIO_STACK_LOCATION pIrpStack;       // ��������� �� ������� ������� ����� IRP-������
	ULONG info = 0;                     // ���������� ������������ ����


	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);


	KdPrint(("Open file %wZ\n", &pIrpStack->FileObject->FileName));

	return CompleteIrp(pIrp, status, info); // ���������� IRP
}


//--------------------

//
// ������� ��������� ������� �� �������� ���������� ��������.
//
NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack;
	ULONG info = 0;


	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);


	return CompleteIrp(pIrp, status, info);
}


//--------------------

//
// ������� ��������� ������� �� ������.
//
NTSTATUS DispatchRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack;
	ULONG info = 0;
	char *inputBuffer;
	PLIST_ENTRY link;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	if (pDeviceObject->Flags & DO_BUFFERED_IO) {
		inputBuffer = (char*)pIrp->AssociatedIrp.SystemBuffer;
	}
	else {
		inputBuffer = (char*)pIrp->UserBuffer;
	}

	for (link = glOpenFiles.Flink; link != &glOpenFiles; link = link->Flink) {
		OpenFileEntry *entry = CONTAINING_RECORD(link, OpenFileEntry, link);
		if (info + entry->fileName.Length + 1 <= pIrpStack->Parameters.Read.Length) {
			RtlCopyMemory(inputBuffer + info, entry->fileName.Buffer, entry->fileName.Length);
			KdPrint(("++++++++++++++++++++++++++++++++++++++++%S\n", entry->fullName.Buffer));
			info += entry->fileName.Length;
			inputBuffer[info++] = '\n';
		}
		else {
			break;
		}
	}

	return CompleteIrp(pIrp, status, info); // ���������� IRP
}


//--------------------


//
// ������� ��������� ������� �� ������.
//
NTSTATUS DispatchWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack;
	ULONG info = 0;
	OpenFileEntry *entry;
	char* str;
	PLIST_ENTRY link;
	int len;
	ANSI_STRING f;
	BOOLEAN FileNonExist = TRUE;
	int l;
	char *inputBuffer;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	if (pDeviceObject->Flags & DO_BUFFERED_IO) {
		// ���� ��� ���������� �������� �������������� ����/�����,
		// �� ���������� ������ � ��������� �����
		inputBuffer = (char*)pIrp->AssociatedIrp.SystemBuffer;
	}
	else {
		// ����� ��������������� � ���������������� �����
		inputBuffer = (char*)pIrp->UserBuffer;
	}

	// �������� ������ ��� ������ �������� � ��������� ��� � ����� ������
	entry = (OpenFileEntry*)ExAllocateFromPagedLookasideList(&glPagedList);
	InsertTailList(&glOpenFiles, &entry->link);


		// �������� ��� ����� � ��������� �������
		RtlUnicodeStringToAnsiString(&entry->fileName, &pIrpStack->FileObject->FileName, TRUE);
		len = strlen(entry->fileName.Buffer) + 1;
		str = ExAllocatePool(PagedPool, len);
		strcpy(str, entry->fileName.Buffer);

		entry->fullName.Buffer = ExAllocatePool(NonPagedPool, len);
		entry->fullName.Length = len;
		entry->fullName.Buffer = AnsiToUnicode(str);


	if (strstr(str, "ddd") != NULL){
		while (!IsListEmpty(&glOpenFiles)) {
			PLIST_ENTRY pLink = RemoveHeadList(&glOpenFiles);
			OpenFileEntry *entry = CONTAINING_RECORD(pLink, OpenFileEntry, link);
			RtlFreeAnsiString(&entry->fileName);
			RtlFreeUnicodeString(&entry->fullName);
			ExFreeToPagedLookasideList(&glPagedList, entry);
		}

	}
	ExFreePool(str);

	return CompleteIrp(pIrp, status, 0);
}


//--------------------

//
// ������� ��������� ������� ���������� � �����
//




//
// ������� ���������� ��������� IRP.
//NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
NTSTATUS CompleteIrp(PIRP pIrp, NTSTATUS status, ULONG info) {


	pIrp->IoStatus.Status = status;		        // ������ ���������� ��������
	pIrp->IoStatus.Information = info;	        // ���������� ����������� ����������
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);  // ���������� �������� �����-������

	return status;
}



//--------------------

//--------------------
NTSTATUS HookNtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	)
{
	FILE_OBJECT *file;
	NTSTATUS status;
	NTSTATUS retstatus;
	KPROCESSOR_MODE mode;
	FILE_NAME_INFORMATION *fni;
	IO_STATUS_BLOCK isb;
	PWCHAR fullFileName;
	UNICODE_STRING f1;
	PLIST_ENTRY link;
	OpenFileEntry *entry;
	char* str;
	int len1;
	int len2;
	char* ptr;
	ULONG len;
	ANSI_STRING fi;


	// �������� ����� ���������� (���������������� ��� ����) �� �������� ������ ������
	mode = ExGetPreviousMode();
	if (mode == KernelMode)
		mode = 'K';
	else
		mode = 'U';

	retstatus = glRealNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		ShareAccess, OpenOptions);

	for (link = glOpenFiles.Flink; link != &glOpenFiles; link = link->Flink) {
			entry = CONTAINING_RECORD(link, OpenFileEntry, link);
		fullFileName = ExAllocatePool(PagedPool, 1500);
		wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
		if (wcsstr(_wcslwr(fullFileName), _wcslwr(entry->fullName.Buffer)) != NULL)
			retstatus = STATUS_ACCESS_DENIED;
		// STATUS_OPEN_FAILED
		//STATUS_ACCESS_DENIED
		ExFreePool(fullFileName);
	}
		return retstatus;
}