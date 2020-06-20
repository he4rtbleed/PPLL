#include "utils.hpp"

BOOLEAN IsBlue = false;
ULONG SignatureLevelOffset{}, SectionSignatureLevelOffset{};

VOID NotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ParentId);
	if (Create)
	{
		PEPROCESS Process;
		PsLookupProcessByProcessId(ProcessId, &Process);
		if (!strcmp((char*)PsGetProcessImageFileName(Process), "yourprocessname.exe"))
		{
			HANDLE hThread{};
			PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, [](PVOID StartContext)
				{
					Sleep(1000);
					if (!SectionSignatureLevelOffset)
					{
						PULONG pFlags2 = (PULONG)(((ULONG_PTR)StartContext) + SignatureLevelOffset);
						*pFlags2 |= PROTECTED_PROCESS_MASK;
					}
					else
					{
						PPROCESS_SIGNATURE_PROTECTION pSignatureProtect = (PPROCESS_SIGNATURE_PROTECTION)(((ULONG_PTR)StartContext) + SignatureLevelOffset);
						pSignatureProtect->SignatureLevel = IsBlue ? 0x0F : 0x3F;
						pSignatureProtect->SectionSignatureLevel = IsBlue ? 0x0F : 0x3F;
						if (!IsBlue)
						{
							pSignatureProtect->Protection.Type = 2;
							pSignatureProtect->Protection.Audit = 0;
							pSignatureProtect->Protection.Signer = 6;
						}
					}
				}
			, Process);
		}
	}
}

_Use_decl_annotations_
VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(DriverObject);
	PsSetCreateProcessNotifyRoutine(&NotifyRoutine, true);
	Log("Driver unloaded.\n");
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(RegistryPath);

	OSVERSIONINFOEXW VersionInfo = { sizeof(OSVERSIONINFOEXW) };
	NTSTATUS Status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&VersionInfo));
	if (!NT_SUCCESS(Status))
		return Status;

	// Only Windows 8.1 and later are afflicted with PPL.
	if (VersionInfo.dwBuildNumber < 6002)
	{
		Log("Unsupported OS version.\n");
		return STATUS_NOT_SUPPORTED;
	}

	if (VersionInfo.dwBuildNumber == 6002)
		SignatureLevelOffset = 0x036c;
	else if (VersionInfo.dwBuildNumber == 7601)
		SignatureLevelOffset = 0x043c;
	else
	{
		if (VersionInfo.dwBuildNumber == 9200)
			IsBlue = true;
		// Find the offsets of the [Section]SignatureLevel fields
		Status = FindSignatureLevelOffsets(&SignatureLevelOffset, &SectionSignatureLevelOffset);
		if (!NT_SUCCESS(Status) && Status != STATUS_NO_MORE_ENTRIES)
		{
			Log("Failed to find the SignatureLevel and SectionSignatureLevel offsets for Windows %u.%u.%u.\n",
				VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber);
			return Status;
		}
	}

	PsSetCreateProcessNotifyRoutine(&NotifyRoutine, false);

	DriverObject->DriverUnload = DriverUnload;

	Log("Driver loaded successfully. You can unload it again now since it doesn't do anything.\n");

	return STATUS_SUCCESS;
}