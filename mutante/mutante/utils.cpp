#include <ntifs.h>
#include <windef.h>
#include <ntimage.h>
#include "shared.h"
#include "utils.h"

/**
 * \brief Get base address of kernel module
 * \param moduleName Name of the module (ex. storport.sys)
 * \return Address of the module or null pointer if failed
 */
PVOID Utils::GetModuleBase(const char* moduleName)
{
	PVOID address = nullptr;
	ULONG size = 0;
	
	auto status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

	auto* moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG));
	if (!moduleList)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
	if (!NT_SUCCESS(status))
		goto end;

	for (auto i = 0; i < moduleList->ulModuleCount; i++)
	{
		auto module = moduleList->Modules[i];
		if (strstr(module.ImageName, moduleName))
		{
			address = module.Base;
			break;
		}
	}
	
end:
	ExFreePool(moduleList);
	return address;
}


/**
 * \brief Checks if buffer at the location of base parameter
 * matches pattern and mask
 * \param base Address to check
 * \param pattern Byte pattern to match
 * \param mask Mask containing unknown bytes
 * \return 
 */
bool Utils::CheckMask(const char* base, const char* pattern, const char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask) 
	{
		if ('x' == *mask && *base != *pattern) 
		{
			return false;
		}
	}

	return true;
}

/**
 * \brief Find byte pattern in given buffer
 * \param base Address to start searching in
 * \param length Maximum length
 * \param pattern Byte pattern to match
 * \param mask Mask containing unknown bytes
 * \return Pointer to matching memory
 */
PVOID Utils::FindPattern(PVOID base, int length, const char* pattern, const char* mask)
{
	length -= static_cast<int>(strlen(mask));
	for (auto i = 0; i <= length; ++i) 
	{
		const auto* data = static_cast<char*>(base);
		const auto* address = &data[i];
		if (CheckMask(address, pattern, mask))
			return PVOID(address);
	}

	return nullptr;
}

/**
 * \brief Find byte pattern in given module/image ".text" and "PAGE" sections
 * \param base Base address of the kernel module
 * \param pattern Byte pattern to match
 * \param mask Mask containing unknown bytes
 * \return Pointer to matching memory
 */
PVOID Utils::FindPatternImage(PVOID base, const char* pattern, const char* mask)
{
	PVOID match = nullptr;

	// Ensure base is valid
	if (!base)
		return nullptr;

	// Calculate the address of the NT headers
	auto* dosHeader = static_cast<PIMAGE_DOS_HEADER>(base);
	auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONG_PTR>(base) + dosHeader->e_lfanew);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	// Get the pointer to the first section
	auto* section = IMAGE_FIRST_SECTION(ntHeaders);
	for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
	{
		// Check if the section is executable
		if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
		{
			// Find the pattern in this section
			match = FindPattern(static_cast<char*>(base) + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match)
				break; // Pattern found, exit the loop
		}
	}

	return match;
}

/**
 * \brief Generate pseudo-random text into given buffer
 * \param text Pointer to text
 * \param length Desired length
 */
void Utils::RandomText(char* text, const int length)
{
	if (!text || length <= 0)
		return;

	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	// Initialize seed with a constant value
	ULONG seed = 12345;

	for (auto n = 0; n < length; n++)
	{
		auto key = RtlRandomEx(&seed) % static_cast<int>(sizeof(alphanum) - 1);
		text[n] = alphanum[key];
	}
	text[length] = '\0'; // Null-terminate the string
}
