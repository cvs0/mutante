#include <ntifs.h>
#include <stdarg.h>
#include "log.h"


/**
 * \brief Prints text to any driver that has registered
 * callback using DbgSetDebugPrintCallback (ex. DbgView)
 * \param text Text to print
 * \param ... printf() style arguments
 */
void Log::Print(const char* text, ...)
{
    if (!text || *text == '\0')
    {
        // Log an error message or handle the empty string appropriately
        return;
    }

    va_list args;
    va_start(args, text);

    vDbgPrintExWithPrefix("[mutante] ", 0, 0, text, args);

    va_end(args);
}
