#pragma once
#include "structure.hpp"
#include <stdio.h>
#include <stdarg.h>

BOOLEAN Sleep(ULONG MillionSecond)
{
	NTSTATUS st;
	LARGE_INTEGER DelayTime;
	DelayTime = RtlConvertLongToLargeInteger(-10000 * MillionSecond);
	st = KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	return (NT_SUCCESS(st));
}

// Source: https://github.com/Mattiwatti/PPLKiller/tree/master/PPLKiller
VOID
Log(
	_In_ PCCH Format,
	_In_ ...
)
{
	CHAR Message[512];
	va_list VaList;
	va_start(VaList, Format);
	CONST ULONG N = _vsnprintf_s(Message, sizeof(Message) - sizeof(CHAR), Format, VaList);
	Message[N] = '\0';
	vDbgPrintExWithPrefix("[PPLL] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Message, VaList);
	va_end(VaList);
}

// This is only called on Windows >= 10.0.15063.0. The 'MS signature required' mitigation
// policy predates that, but the kernel mode check in MiValidateSectionCreate does not
NTSTATUS
FindSignatureLevelOffsets(
	_Out_ PULONG SignatureLevelOffset,
	_Out_ PULONG SectionSignatureLevelOffset
)
{
	PAGED_CODE();

	*SignatureLevelOffset = 0;
	*SectionSignatureLevelOffset = 0;

	// Since the EPROCESS struct is opaque and we don't know its size, allocate for 4K possible offsets
	const PULONG CandidateSignatureLevelOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
			PAGE_SIZE * sizeof(ULONG),
			'PPLL'));
	if (CandidateSignatureLevelOffsets == nullptr)
		return STATUS_NO_MEMORY;
	const PULONG CandidateSectionSignatureLevelOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
			PAGE_SIZE * sizeof(ULONG),
			'PPLL'));
	if (CandidateSectionSignatureLevelOffsets == nullptr)
	{
		ExFreePoolWithTag(CandidateSignatureLevelOffsets, 'PPLL');
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(CandidateSignatureLevelOffsets, sizeof(ULONG) * PAGE_SIZE);
	RtlZeroMemory(CandidateSectionSignatureLevelOffsets, sizeof(ULONG) * PAGE_SIZE);

	// Query all running processes
	ULONG NumSignatureRequiredProcesses = 0, BestMatchCount = 0;
	ULONG SignatureOffset = 0, SectionSignatureOffset = 0;
	NTSTATUS Status;
	ULONG Size;
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
	if ((Status = ZwQuerySystemInformation(SystemProcessInformation,
		SystemProcessInfo,
		0,
		&Size)) != STATUS_INFO_LENGTH_MISMATCH)
		goto finished;
	SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
			2 * Size,
			'PPLL'));
	if (SystemProcessInfo == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}
	Status = ZwQuerySystemInformation(SystemProcessInformation,
		SystemProcessInfo,
		2 * Size,
		nullptr);
	if (!NT_SUCCESS(Status))
		goto finished;

	// Enumerate the process list
	Entry = SystemProcessInfo;
	while (true)
	{
		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(static_cast<PUNICODE_STRING>(nullptr),
			OBJ_KERNEL_HANDLE);
		CLIENT_ID ClientId = { Entry->UniqueProcessId, nullptr };
		HANDLE ProcessHandle;
		Status = ZwOpenProcess(&ProcessHandle,
			PROCESS_QUERY_LIMITED_INFORMATION,
			&ObjectAttributes,
			&ClientId);
		if (NT_SUCCESS(Status))
		{
			// Query the process's signature policy status
			PROCESS_MITIGATION_POLICY_INFORMATION PolicyInfo;
			PolicyInfo.Policy = ProcessSignaturePolicy;
			Status = ZwQueryInformationProcess(ProcessHandle,
				ProcessMitigationPolicy,
				&PolicyInfo,
				sizeof(PolicyInfo),
				nullptr);

			// If it has an MS signature policy requirement, get the EPROCESS
			if (NT_SUCCESS(Status) && PolicyInfo.u.SignaturePolicy.MicrosoftSignedOnly != 0)
			{
				PEPROCESS Process;
				Status = ObReferenceObjectByHandle(ProcessHandle,
					PROCESS_QUERY_LIMITED_INFORMATION,
					*PsProcessType,
					KernelMode,
					reinterpret_cast<PVOID*>(&Process),
					nullptr);
				if (NT_SUCCESS(Status))
				{
					// Find plausible offsets in the EPROCESS
					const ULONG_PTR End = ALIGN_UP_BY(Process, PAGE_SIZE) - reinterpret_cast<ULONG_PTR>(Process) - sizeof(UCHAR);
					for (ULONG_PTR i = PS_SEARCH_START; i < End; ++i)
					{
						// Take the low nibble of both bytes, which contains the SE_SIGNING_LEVEL_*
						const UCHAR CandidateSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i) & 0xF;
						const ULONG CandidateSectionSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i + sizeof(UCHAR)) & 0xF;

						if ((CandidateSignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_WINDOWS ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_ANTIMALWARE ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_WINDOWS_TCB)
							&&
							(CandidateSectionSignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
								CandidateSectionSignatureLevel == SE_SIGNING_LEVEL_WINDOWS))
						{
							CandidateSignatureLevelOffsets[i]++;
							i += sizeof(UCHAR);
							CandidateSectionSignatureLevelOffsets[i]++;
						}
					}
					NumSignatureRequiredProcesses++;
					ObfDereferenceObject(Process);
				}
			}
			ZwClose(ProcessHandle);
		}

		if (Entry->NextEntryOffset == 0)
			break;

		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
			Entry->NextEntryOffset);
	}

	// Go over the possible offsets to find the combination that is correct for all processes
	for (ULONG i = PS_SEARCH_START; i < PAGE_SIZE; ++i)
	{
		if (CandidateSignatureLevelOffsets[i] > BestMatchCount)
		{
			if (BestMatchCount == NumSignatureRequiredProcesses)
			{
				Log("Found multiple offsets for SignatureLevel that match all processes! This is probably a bug - please report.\n");
				Status = STATUS_NOT_FOUND;
				goto finished;
			}
			SignatureOffset = i;
			SectionSignatureOffset = i + sizeof(UCHAR);
			BestMatchCount = CandidateSignatureLevelOffsets[i];
		}
	}

	if (BestMatchCount == 0 && NumSignatureRequiredProcesses > 0)
	{
		Log("Did not find any possible offsets for the SignatureLevel field.\n");
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (BestMatchCount != NumSignatureRequiredProcesses)
	{
		Log("Best found SignatureLevel offset match +0x%02X is only valid for %u of %u processes.\n",
			SignatureOffset, BestMatchCount, NumSignatureRequiredProcesses);
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (NumSignatureRequiredProcesses > 1) // Require at least System + 1 other MS signing policy process to give a reliable result
		Log("Found SignatureLevel offset +0x%02X and SectionSignatureLevel offset +0x%02X.\n\n",
			SignatureOffset, SectionSignatureOffset);
	else
	{
		// This is not an error condition; it just means there are no processes with MS code signing requirements.
		// There may still be PPLs to kill. Set a non-error status to indicate this.
		Log("Did not find any non-system processes with signature requirements.\n");
		Status = STATUS_NO_MORE_ENTRIES;
		SignatureOffset = 0;
		SectionSignatureOffset = 0;
	}
	*SignatureLevelOffset = SignatureOffset;
	*SectionSignatureLevelOffset = SectionSignatureOffset;

finished:
	if (SystemProcessInfo != nullptr)
		ExFreePoolWithTag(SystemProcessInfo, 'PPLL');
	ExFreePoolWithTag(CandidateSectionSignatureLevelOffsets, 'PPLL');
	ExFreePoolWithTag(CandidateSignatureLevelOffsets, 'PPLL');
	return Status;
}