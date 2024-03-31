#include <ntifs.h>
#include "log.h"
#include "utils.h"
#include "shared.h"
#include "smbios.h"

/**
 * \brief Get's the string from SMBIOS table
 * \param header Table header
 * \param string String itself
 * \return Pointer to the null terminated string
 */
char* Smbios::GetString(SMBIOS_HEADER* header, SMBIOS_STRING string)
{
	if (!header || string == 0)
		return nullptr;

	const char* start = reinterpret_cast<const char*>(header) + header->Length;

	while (--string)
	{
		start += strlen(start) + 1;
		if (*start == '\0') // Check for premature end of strings
			return nullptr;
	}

	return const_cast<char*>(start);
}

/**
 * \brief Replace string at a given location by randomized string with the same length
 * \param string Pointer to string (has to be null terminated)
 */
void Smbios::RandomizeString(char* string)
{
	if (!string)
		return;

	size_t length = strlen(string);
	if (length == 0)
		return;

	char* buffer = static_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, length + 1, POOL_TAG));
	if (!buffer)
		return;

	Utils::RandomText(buffer, static_cast<int>(length));
	buffer[length] = '\0';

	strcpy_s(string, length + 1, buffer);

	ExFreePool(buffer);
}

/**
 * \brief Check if the string number in an SMBIOS structure is valid and null-terminated
 * \param header Pointer to the SMBIOS header
 * \param stringNumber String number to check
 * \return true if the string is valid and null-terminated, false otherwise
 */
bool Smbios::IsValidString(SMBIOS_HEADER* header, UCHAR stringNumber)
{
	// Check if the string number is within bounds
	if (stringNumber == 0 || stringNumber >= header->Length)
		return false;

	// Get a pointer to the start of the SMBIOS structure
	auto* start = reinterpret_cast<char*>(header);

	// Find the start of the string by iterating through the structure bytes
	char* stringStart = start + header->Length;
	for (UCHAR i = 1; i < stringNumber; ++i)
	{
		// Move to the next string (find the next null terminator)
		while (*stringStart++ != '\0');

		// Check if we reached the end of the structure
		if (stringStart >= start + header->Length)
			return false;
	}

	// Check if the string is null-terminated
	if (*stringStart != '\0')
		return false;

	return true;
}


/**
 * \brief Modify information in the table of given header
 * \param header Table header (only 0-3 implemented)
 * \return 
 */
NTSTATUS Smbios::ProcessTable(SMBIOS_HEADER* header)
{
	if (!header || header->Length == 0)
		return STATUS_INVALID_PARAMETER;

	switch (header->Type)
	{
	case 0:
	{
		auto* type0 = reinterpret_cast<SMBIOS_TYPE0*>(header);
		if (!IsValidString(header, type0->Vendor))
			return STATUS_UNSUCCESSFUL;

		RandomizeString(GetString(header, type0->Vendor));
		break;
	}
	case 1:
	{
		auto* type1 = reinterpret_cast<SMBIOS_TYPE1*>(header);
		if (!IsValidString(header, type1->Manufacturer) ||
			!IsValidString(header, type1->ProductName) ||
			!IsValidString(header, type1->SerialNumber))
			return STATUS_UNSUCCESSFUL;

		RandomizeString(GetString(header, type1->Manufacturer));
		RandomizeString(GetString(header, type1->ProductName));
		RandomizeString(GetString(header, type1->SerialNumber));
		break;
	}
	case 2:
	{
		auto* type2 = reinterpret_cast<SMBIOS_TYPE2*>(header);
		if (!IsValidString(header, type2->Manufacturer) ||
			!IsValidString(header, type2->ProductName) ||
			!IsValidString(header, type2->SerialNumber))
			return STATUS_UNSUCCESSFUL;

		RandomizeString(GetString(header, type2->Manufacturer));
		RandomizeString(GetString(header, type2->ProductName));
		RandomizeString(GetString(header, type2->SerialNumber));
		break;
	}
	case 3:
	{
		auto* type3 = reinterpret_cast<SMBIOS_TYPE3*>(header);
		if (!IsValidString(header, type3->Manufacturer) ||
			!IsValidString(header, type3->SerialNumber))
			return STATUS_UNSUCCESSFUL;

		RandomizeString(GetString(header, type3->Manufacturer));
		RandomizeString(GetString(header, type3->SerialNumber));
		break;
	}
	default:
		// Unsupported SMBIOS type, just return success
		break;
	}

	return STATUS_SUCCESS;
}


/**
 * \brief Loop through SMBIOS tables with provided first table header
 * \param mapped Header of the first table
 * \param size Size of all tables including strings
 * \return 
 */
NTSTATUS Smbios::LoopTables(void* mapped, ULONG size)
{
	if (!mapped || size < sizeof(SMBIOS_HEADER))
	{
		Log::Print("Invalid parameters for LoopTables!\n");
		return STATUS_INVALID_PARAMETER;
	}

	auto* endAddress = static_cast<char*>(mapped) + size;

	while (true)
	{
		auto* header = static_cast<SMBIOS_HEADER*>(mapped);

		// Check if the header is valid
		if ((char*)header + sizeof(SMBIOS_HEADER) > endAddress)
		{
			Log::Print("Invalid SMBIOS header!\n");
			return STATUS_INVALID_PARAMETER;
		}

		if (header->Type == 127 && header->Length == 4)
			break;

		ProcessTable(header);

		// Find the end of the current SMBIOS table
		auto* end = static_cast<char*>(mapped) + header->Length;
		while (*(end - 1) == 0)
			end--;

		// Move to the next SMBIOS table
		mapped = end;
		if (mapped >= endAddress)
			break;
	}

	return STATUS_SUCCESS;
}

/**
 * \brief Find SMBIOS physical address, map it and then loop through
 * table 0-3 and modify possible identifiable information
 * \return Status of the change (will return STATUS_SUCCESS if mapping was successful)
 */
NTSTATUS Smbios::ChangeSmbiosSerials()
{
	auto* base = Utils::GetModuleBase("ntoskrnl.exe");
	if (!base)
	{
		Log::Print("Failed to find ntoskrnl.sys base!\n");
		return STATUS_UNSUCCESSFUL;
	}

	auto* physicalAddressPattern = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15";
	auto* physicalAddress = static_cast<PPHYSICAL_ADDRESS>(Utils::FindPatternImage(base, physicalAddressPattern, "xxx????xxxx?xx"));
	if (!physicalAddress)
	{
		Log::Print("Failed to find SMBIOS physical address!\n");
		return STATUS_UNSUCCESSFUL;
	}

	physicalAddress = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(physicalAddress) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(physicalAddress) + 3));
	if (!physicalAddress)
	{
		Log::Print("Physical address is null!\n");
		return STATUS_UNSUCCESSFUL;
	}

	auto* sizeScanPattern = "\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B";
	auto* sizeScan = Utils::FindPatternImage(base, sizeScanPattern, "xx????xxxxxxxxxx????xxxx");
	if (!sizeScan)
	{
		Log::Print("Failed to find SMBIOS size!\n");
		return STATUS_UNSUCCESSFUL;
	}

	const auto size = *reinterpret_cast<ULONG*>(static_cast<char*>(sizeScan) + 6 + *reinterpret_cast<int*>(static_cast<char*>(sizeScan) + 2));
	if (!size)
	{
		Log::Print("SMBIOS size is null!\n");
		return STATUS_UNSUCCESSFUL;
	}

	auto* mapped = MmMapIoSpace(*physicalAddress, size, MmNonCached);
	if (!mapped)
	{
		Log::Print("Failed to map SMBIOS structures!\n");
		return STATUS_UNSUCCESSFUL;
	}

	LoopTables(mapped, size);

	MmUnmapIoSpace(mapped, size);

	return STATUS_SUCCESS;
}
