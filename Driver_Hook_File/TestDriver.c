#include <ntddk.h>


//*************************************************************
// макросы и глобальные переменные


#define	SYM_LINK_NAME   L"\\Global??\\Driver"
#define DEVICE_NAME     L"\\Device\\DDriver"


UNICODE_STRING glDeviceName;
UNICODE_STRING glSymLinkName;
ULONG len = 1000;

ULONG glHookCounter;


LIST_ENTRY glOpenFiles;
PAGED_LOOKASIDE_LIST glPagedList;

typedef struct _OpenFileEntry {

	ANSI_STRING fileName;
	UNICODE_STRING fullName;
	LIST_ENTRY link;

} OpenFileEntry;

// таблица системных вызовов
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;        // массив адресов системных вызовов(сервисов)
	PULONG Count;           // массив счётчиков вызовов сервисов
	ULONG Limit;            // количество вызовов в таблице
	PUCHAR Number;          // массив количества параметров вызовов(в байтах)
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

// прототип функции NtCreateFile
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

// номер вызова NtCreateFile в таблице системных вызовов
#define NUMBER_NT_CREATE_FILE   0x25
#define NUMBER_NT_OPEN_FILE		0x74



//*************************************************************
// предварительное объявление функций
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
// предварительное объявление функций


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
// описание функций
// глобальные переменные

// адрес функции NtCreateFile
NT_CREATE_FILE glRealNtCreateFile;
NT_OPEN_FILE glRealNtOpenFile;

UNICODE_STRING glProtectedFiles[2];

// таблица системных вызовов
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;


//*************************************************************
// описание функций

void WaitHookUnload(ULONG *p) {

	KEVENT event;
	LARGE_INTEGER time;

	time.QuadPart = -10000000;

	KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	while (*p) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &time);
	}
}
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
	do
		uniStr.Buffer = (PWCH)ExAllocatePool(NonPagedPool, length);
	while (uniStr.Buffer == NULL);
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
// Функция инициализации драйвера.
//
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING RegistryPath) {

	PDEVICE_OBJECT  pDeviceObject;				// указатель на объект устройство
	NTSTATUS		status = STATUS_SUCCESS;	// статус завершения функции
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
	pDriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = DispatchQueryInformation;
	//pDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = DispatchSetInformation;

	pDriverObject->DriverUnload = DriverUnload;

	KdPrint(("Load driver %wZ\n", &pDriverObject->DriverName));
	KdPrint(("Registry path %wZ\n", RegistryPath));

	RtlInitUnicodeString(&glDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&glSymLinkName, SYM_LINK_NAME);

	// создание устройства
	status = IoCreateDevice(pDriverObject,         // указатель на объект драйвера
		0,                     // размер области дополнительной памяти устройства
		&glDeviceName,         // имя устройства
		FILE_DEVICE_UNKNOWN,   // идентификатор типа устройства
		0,                     // дополнительная информация об устройстве
		FALSE,                 // используется системой(для драйверов должно быть FALSE)
		&pDeviceObject);       // адрес для сохранения указателя на объект устройства
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// буферизованный ввод/вывод для операций чтения/записи
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	KdPrint(("Create device %wZ\n", &glDeviceName));

	// создание символьной ссылки
	status = IoCreateSymbolicLink(&glSymLinkName, &glDeviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	KdPrint(("Create symbolic link %wZ\n", &glSymLinkName));

	// создаем резервный список
	ExInitializePagedLookasideList(&glPagedList, NULL, NULL, 0, sizeof(OpenFileEntry), ' LFO', 0);

	InitializeListHead(&glOpenFiles);

	// запоминаем адрес реального обработчика вызова NtCreateFile
	glRealNtCreateFile = (NT_CREATE_FILE)KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE];
	glRealNtOpenFile = (NT_OPEN_FILE)KeServiceDescriptorTable->Base[NUMBER_NT_OPEN_FILE];
	//glRealNtOpenFile = KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE];
	// подставляем адрес нового обработчика
	//reg = ClearWP();
	KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE] = (ULONG)HookNtCreateFile;
	KeServiceDescriptorTable->Base[NUMBER_NT_OPEN_FILE] = (ULONG)HookNtOpenFile;
	//WriteCR0(reg);

	return status;
}


//--------------------

//
// Функция, вызываемая при выгрузке драйвера.
//
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject) {
	ULONG reg;

	// удаление символьной ссылки и объекта устройства
	IoDeleteSymbolicLink(&glSymLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	// удаляем элементы списка файлов
	while (!IsListEmpty(&glOpenFiles)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glOpenFiles);
		OpenFileEntry *entry = CONTAINING_RECORD(pLink, OpenFileEntry, link);

		RtlFreeAnsiString(&entry->fileName);
		RtlFreeUnicodeString(&entry->fullName);

		ExFreeToPagedLookasideList(&glPagedList, entry);
	}

	// удаляем резервный список
	ExDeletePagedLookasideList(&glPagedList);

	KdPrint(("Driver unload\n"));
	//reg = ClearWP();
	KeServiceDescriptorTable->Base[NUMBER_NT_CREATE_FILE] = (ULONG)glRealNtCreateFile;
	KeServiceDescriptorTable->Base[NUMBER_NT_OPEN_FILE] = (ULONG)glRealNtOpenFile;
	//WriteCR0(reg);

	WaitHookUnload(&glHookCounter);
	//FreeProtectedFiles();

	return;
}
//----------------------------------------

// функция-обработчик системного вызова NtCreateFile
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
	NTSTATUS status;
	NTSTATUS retstatus;
	KPROCESSOR_MODE mode;
	FILE_NAME_INFORMATION *fni;
	IO_STATUS_BLOCK isb;
	PWCHAR fullFileName;
	//UNICODE_STRING f1;
	PLIST_ENTRY link;
	OpenFileEntry *entry;
	//char* str;
	//int len1;
	//int len2;
	//char* ptr;

	++glHookCounter;


	mode = ExGetPreviousMode();
	if (mode == KernelMode)
		mode = 'K';
	else
		mode = 'U';

	retstatus = glRealNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);


	if (ObjectAttributes->RootDirectory){
		do
			fni = (FILE_NAME_INFORMATION*)ExAllocatePool(PagedPool, 0x1000);
		while (fni == NULL);
		if (!fni){

		}
		else{

			status = ZwQueryInformationFile(
				ObjectAttributes->RootDirectory,   // описатель файла
				&isb,                              // адрес структуры IO_STATUS_BLOCK
				fni,                               // буфер для сохранения информации
				0x1000,                            // размер буфера
				FileNameInformation                // тип информации - имя файла
				);
			if (NT_SUCCESS(status)){
				fni->FileName[(isb.Information - 4) / 2] = 0;
				do
					fullFileName = ExAllocatePool(PagedPool, fni->FileNameLength + ObjectAttributes->ObjectName->Length + 2);
				while (fullFileName == NULL);

				wcscpy(fullFileName, fni->FileName);
				wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
				DbgPrint("%c: %d.%d (%X)\t FullFileName - %S\n", mode, PsGetCurrentProcessId(), PsGetCurrentThreadId(), retstatus, fullFileName);
			}
			else{
				do
					fullFileName = ExAllocatePool(PagedPool, ObjectAttributes->ObjectName->Length + 2);
				while (fullFileName == NULL);
				wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);

				DbgPrint("%c: %d.%d (%X)\tFullFileName - %S\n", mode, PsGetCurrentProcessId(), PsGetCurrentThreadId(), retstatus, fullFileName);
			}
			ExFreePool(fni);
		}
	}
	else {
		do
			fullFileName = ExAllocatePool(PagedPool, ObjectAttributes->ObjectName->Length + 2);
		while (fullFileName == NULL);
		wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);

		DbgPrint("%c: %d.%d (%X)\tFullFileName: %S\n", mode, PsGetCurrentProcessId(), PsGetCurrentThreadId(), retstatus, fullFileName);
	}

	for (link = glOpenFiles.Flink; link != &glOpenFiles; link = link->Flink) {
		entry = CONTAINING_RECORD(link, OpenFileEntry, link);
		if (wcsstr(_wcslwr(fullFileName), _wcslwr(entry->fullName.Buffer)) != NULL)
			retstatus = STATUS_ACCESS_DENIED;
	}
	ExFreePool(fullFileName);

	--glHookCounter;
	return retstatus;
}

//
// Функция обработки запроса на открытие устройства драйвера.
//
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS status = STATUS_SUCCESS;   // статус завершения операции ввода/вывода
	PIO_STACK_LOCATION pIrpStack;       // указатель на текущий элемент стека IRP-пакета
	ULONG info = 0;                     // количество возвращённых байт


	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	KdPrint(("Open file %wZ\n", &pIrpStack->FileObject->FileName));

	return CompleteIrp(pIrp, status, info); // Завершение IRP
}


//--------------------

//
// Функция обработки запроса на закрытие устройства драйвера.
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
// Функция обработки запроса на чтение.
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
			info += entry->fileName.Length;
			inputBuffer[info++] = '\n';
		}
		else {
			break;
		}
	}
	return CompleteIrp(pIrp, status, info); // Завершение IRP
}


//--------------------


//
// Функция обработки запроса на запись.
//
NTSTATUS DispatchWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack;
	ULONG info = 0;
	OpenFileEntry *entry;
	char* str;
	char* str1;
	PLIST_ENTRY link;
	int len;
	ANSI_STRING f;
	BOOLEAN FileNonExist = TRUE;
	int l;
	char *inputBuffer;
	int i;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	if (pDeviceObject->Flags & DO_BUFFERED_IO) {
		// если для устройства определён буферизованный ввод/вывод,
		// то записываем данные в системный буфер
		inputBuffer = (char*)pIrp->AssociatedIrp.SystemBuffer;
	}
	else {
		// иначе непосредственно в пользовательский буфер
		inputBuffer = (char*)pIrp->UserBuffer;
	}

	// выделяем память для нового элемента и вставляем его в конец списка
	entry = (OpenFileEntry*)ExAllocateFromPagedLookasideList(&glPagedList);
	InsertTailList(&glOpenFiles, &entry->link);


	// копируем имя файла в созданный элемент
	RtlUnicodeStringToAnsiString(&entry->fileName, &pIrpStack->FileObject->FileName, TRUE);
	len = strlen(entry->fileName.Buffer) + 1;
	do
		str = ExAllocatePool(NonPagedPool, len);
	while (str == NULL);
	strcpy(str, entry->fileName.Buffer);
	if (strstr(str, "??") != NULL){
		do
			str1 = ExAllocatePool(NonPagedPool, len - 4);
		while (str1 == NULL);
		strcpy(str1, &str[4]);
		do
			entry->fullName.Buffer = AnsiToUnicode(str1);
		while (entry->fullName.Buffer == NULL);

		ExFreePool(str1);
	}
	else
		entry->fullName.Buffer = AnsiToUnicode(str);

	//если ввели "ddd" отчищаем весь список хукнутых файлов
	if (strstr(str, "ddd") != NULL){
		while (!IsListEmpty(&glOpenFiles)) {
			PLIST_ENTRY pLink = RemoveHeadList(&glOpenFiles);
			entry = CONTAINING_RECORD(pLink, OpenFileEntry, link);
			RtlFreeAnsiString(&entry->fileName);
			RtlFreeUnicodeString(&entry->fullName);
			ExFreeToPagedLookasideList(&glPagedList, entry);
		}

	}
	ExFreePool(str);

	return CompleteIrp(pIrp, status, info);
}
//
// Функция завершения обработки IRP.
//NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
NTSTATUS CompleteIrp(PIRP pIrp, NTSTATUS status, ULONG info) {


	pIrp->IoStatus.Status = status;		        // статус завершении операции
	pIrp->IoStatus.Information = info;	        // количество возращаемой информации
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);  // завершение операции ввода-вывода

	return status;
}



//--------------------
// Функция обработки запроса информации о файле
//
NTSTATUS DispatchQueryInformation(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack;
	ULONG info = 0;
	FILE_BASIC_INFORMATION *fbi;
	FILE_STANDARD_INFORMATION *fsi;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	switch (pIrpStack->Parameters.QueryFile.FileInformationClass) {

	case FileStandardInformation:
		info = sizeof(FILE_STANDARD_INFORMATION);
		if (info > pIrpStack->Parameters.QueryFile.Length) {
			info = 0;
			break;
		}

		fsi = (FILE_STANDARD_INFORMATION*)pIrp->AssociatedIrp.SystemBuffer;
		fsi->AllocationSize.QuadPart = 0;
		fsi->EndOfFile.QuadPart = 1000;  // размер файла
		fsi->NumberOfLinks = 1;             // количество жёстких ссылок
		fsi->Directory = FALSE;
		fsi->DeletePending = FALSE;
		break;
	}

	return CompleteIrp(pIrp, status, info);
}
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
	ANSI_STRING fi;

	++glHookCounter;

	// получаем режим процессора (пользовательский или ядра) из которого пришёл запрос
	mode = ExGetPreviousMode();
	if (mode == KernelMode)
		mode = 'K';
	else
		mode = 'U';

	retstatus = glRealNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		ShareAccess, OpenOptions);

	if (ObjectAttributes->RootDirectory) {
		// выделения памяти для информации о файле
		do
			fni = (FILE_NAME_INFORMATION*)ExAllocatePool(PagedPool, 0x1000);
		while (fni == NULL);
		if (!fni) {
			do
				fullFileName = ExAllocatePool(PagedPool, len + ObjectAttributes->ObjectName->Length + 2);
			while (fullFileName == NULL);
			KdPrint(("STR %S\n", ObjectAttributes->ObjectName->Buffer));
			KdPrint(("LEN %d\n", ObjectAttributes->ObjectName->Length));
			//wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
		}
		else {
			status = ObReferenceObjectByHandle(
				ObjectAttributes->RootDirectory,    // описатель
				0,                                  // права доступа
				*IoFileObjectType,                  // указатель на объект "Тип" для данного объекта
				KernelMode,                         // уровень доступа
				// KernelMode - доступ из ядра
				// UserMode - доступ из пользовательского режима
				// Так как мы указали доступ из ядра,
				// то права доступа и указатель на объект "Тип" не обязательны.
				// Но, т.к. указатель на объект "Тип" указан, то система проверяет,
				// что тип объекта по описателю совпадает с указанным.
				&file,                              // указатель для сохранения указателя на объект
				NULL);                              // указатель для получения дополнительной информации об описателе

			if (NT_SUCCESS(status)) {
				UNICODE_STRING diskName;
				file->FileName.Buffer[file->FileName.Length / 2] = 0;

				status = IoVolumeDeviceToDosName(file->DeviceObject, &diskName);
				if (NT_SUCCESS(status)) {
					diskName.Buffer[diskName.Length / 2] = 0;
					do
						fullFileName = ExAllocatePool(PagedPool,
						file->FileName.Length + len + diskName.Length + ObjectAttributes->ObjectName->Length + 2);
					while (fullFileName == NULL);
					KdPrint(("STR %S\n", ObjectAttributes->ObjectName->Buffer));
					KdPrint(("LEN %d\n", ObjectAttributes->ObjectName->Length));

					//wcscpy(fullFileName, diskName.Buffer);
				}
				else {
					do
						fullFileName = ExAllocatePool(PagedPool,
						file->FileName.Length + len + ObjectAttributes->ObjectName->Length + 2);
					while (fullFileName == NULL);
					KdPrint(("STR %S\n", ObjectAttributes->ObjectName->Buffer));
					KdPrint(("LEN %d\n", ObjectAttributes->ObjectName->Length));

					//wcscpy(fullFileName, L"");
				}

				wcscat(fullFileName, file->FileName.Buffer);
				wcscat(fullFileName, ObjectAttributes->ObjectName->Buffer);
				ObDereferenceObject(file);
			}
			else {
				do
					fullFileName = ExAllocatePool(PagedPool, len + ObjectAttributes->ObjectName->Length + 2);
				while (fullFileName == NULL);
				KdPrint(("STR %S\n", ObjectAttributes->ObjectName->Buffer));
				KdPrint(("LEN %d\n", ObjectAttributes->ObjectName->Length));
				//wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
			}
			ExFreePool(fni);
		}
	}
	else {
		do
			fullFileName = ExAllocatePool(PagedPool, len + ObjectAttributes->ObjectName->Length + 2);
		while (fullFileName == NULL);
		KdPrint(("STR %S\n", ObjectAttributes->ObjectName->Buffer));
		KdPrint(("LEN %d\n", ObjectAttributes->ObjectName->Length));
		//wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
	}
	ExFreePool(fullFileName);
	//если раскоментить wcscpy , что сверху, то драйвер будет падать, 
	//по-этому нужно поработать над этим(Маткину не очень нравится)
	//падает изза того, что в какой то момент, выделяется мало памяти, а дальше происходт запись в "0"
	//и начиная с if (ObjectAttributes->RootDirectory) идет по идее бесполезный код
	//по-этому дальше идет "костыль"
	do
		fullFileName = ExAllocatePool(NonPagedPool, len + ObjectAttributes->ObjectName->Length + 2);
	while (fullFileName == NULL);
	wcscpy(fullFileName, ObjectAttributes->ObjectName->Buffer);
	//"костыль" заключается в том , что я выделяю память предварительно больше чем нужно
	//за это отвечает глобальная переменная len

	//бегаем по списку
		for (link = glOpenFiles.Flink; link != &glOpenFiles; link = link->Flink) {
			entry = CONTAINING_RECORD(link, OpenFileEntry, link);
			//ищим вхождения имени \file_name
			if (wcsstr(_wcslwr(fullFileName), _wcslwr(entry->fullName.Buffer)) != NULL)
				retstatus = STATUS_ACCESS_DENIED;
			// STATUS_OPEN_FAILED
			//STATUS_ACCESS_DENIED
		}
		ExFreePool(fullFileName);

		--glHookCounter;
		return retstatus;
	}
