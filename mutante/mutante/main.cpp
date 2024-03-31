/*
 * Mutante
 * Made by Samuel Tulach
 * https://github.com/SamuelTulach/mutante
 */

#include <ntifs.h>
#include "log.h"
#include "shared.h"
#include "disks.h"
#include "smbios.h"

 /**
  * \brief Driver's main entry point
  * \param object Pointer to driver object (invalid when manually mapped)
  * \param registry Registry path (invalid when manually mapped)
  * \return Status of the driver execution
  */
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT object, PUNICODE_STRING registry)
{
    UNREFERENCED_PARAMETER(object);
    UNREFERENCED_PARAMETER(registry);

    // Log driver load information
    Log::Print("Driver loaded. Build on %s.", __DATE__);

    // Perform driver initialization tasks
    Disks::DisableSmart();
    Disks::ChangeDiskSerials();
    Smbios::ChangeSmbiosSerials();

    return STATUS_SUCCESS;
}
