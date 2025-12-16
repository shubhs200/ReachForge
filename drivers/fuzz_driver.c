#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

// MM + cFE public headers
#include "mm_msg.h"
#include "mm_dump.h"
#include "mm_load.h"
#include "mm_app.h"
#include "mm_msgids.h"

#include "cfe.h"

// -----------------------------------------------------------------------------
// Use the real MM app data from mm_app.c
// -----------------------------------------------------------------------------
extern MM_AppData_t MM_AppData;

// -----------------------------------------------------------------------------
// Minimal stub implementations for external dependencies (same as mm_afl_harness)
// -----------------------------------------------------------------------------

// Event Service stubs
CFE_Status_t CFE_EVS_SendEvent(uint16 EventID, CFE_EVS_EventType_Enum_t EventType, const char *Spec, ...)
{
    (void)EventID;
    (void)EventType;
    (void)Spec;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_EVS_Register(const void *Filters, uint16 NumEventFilters, uint16 FilterScheme)
{
    (void)Filters;
    (void)NumEventFilters;
    (void)FilterScheme;
    return CFE_SUCCESS;
}

// Performance logging stub function used by macros CFE_ES_PerfLogEntry/Exit
void CFE_ES_PerfLogAdd(uint32 Marker, uint32 EntryExit)
{
    (void)Marker;
    (void)EntryExit;
}

CFE_Status_t CFE_ES_WriteToSysLog(const char *SpecStringPtr, ...)
{
    (void)SpecStringPtr;
    return CFE_SUCCESS;
}

void CFE_ES_ExitApp(uint32 RunStatus)
{
    (void)RunStatus;
}

bool CFE_ES_RunLoop(uint32 *RunStatus)
{
    (void)RunStatus;
    return false;
}

// Software Bus stubs
CFE_Status_t CFE_SB_CreatePipe(CFE_SB_PipeId_t *PipeIdPtr, uint16 Depth, const char *PipeName)
{
    (void)Depth;
    (void)PipeName;
    if (PipeIdPtr)
    {
        *PipeIdPtr = 1;
    }
    return CFE_SUCCESS;
}

CFE_Status_t CFE_SB_Subscribe(CFE_SB_MsgId_t MsgId, CFE_SB_PipeId_t PipeId)
{
    (void)MsgId;
    (void)PipeId;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_SB_ReceiveBuffer(CFE_SB_Buffer_t **BufPtr, CFE_SB_PipeId_t PipeId, int32 TimeOut)
{
    (void)BufPtr;
    (void)PipeId;
    (void)TimeOut;
    return CFE_SB_TIME_OUT;
}

void CFE_SB_TimeStampMsg(CFE_MSG_Message_t *MsgPtr)
{
    (void)MsgPtr;
}

CFE_Status_t CFE_SB_TransmitMsg(const CFE_MSG_Message_t *MsgPtr, bool IsOrigination)
{
    (void)MsgPtr;
    (void)IsOrigination;
    return CFE_SUCCESS;
}

// File Services stubs
void CFE_FS_InitHeader(CFE_FS_Header_t *Hdr, const char *Descr, uint32 SubType)
{
    (void)Hdr;
    (void)Descr;
    (void)SubType;
}

int32 CFE_FS_WriteHeader(osal_id_t FileHandle, CFE_FS_Header_t *Hdr)
{
    (void)FileHandle;
    (void)Hdr;
    return (int32)sizeof(CFE_FS_Header_t);
}

int32 CFE_FS_ReadHeader(CFE_FS_Header_t *Hdr, osal_id_t FileHandle)
{
    (void)Hdr;
    (void)FileHandle;
    return (int32)sizeof(CFE_FS_Header_t);
}

// OSAL stubs
int32 OS_OpenCreate(osal_id_t *filedes, const char *path, int32 flags, int32 access)
{
    (void)filedes;
    (void)path;
    (void)flags;
    (void)access;
    return 0;
}

int32 OS_close(osal_id_t filedes)
{
    (void)filedes;
    return 0;
}

int32 OS_write(osal_id_t filedes, const void *buffer, size_t nbytes)
{
    (void)filedes;
    (void)buffer;
    return (int32)nbytes;
}

int32 OS_read(osal_id_t filedes, void *buffer, size_t nbytes)
{
    (void)filedes;
    memset(buffer, 0, nbytes);
    return (int32)nbytes;
}

int32 OS_lseek(osal_id_t filedes, int32 offset, uint32 whence)
{
    (void)filedes;
    (void)whence;
    return offset;
}

int32 OS_stat(const char *path, os_fstat_t *filestats)
{
    (void)path;
    memset(filestats, 0, sizeof(*filestats));
    return 0;
}

int32 OS_TaskDelay(uint32 Millisecs)
{
    (void)Millisecs;
    return 0;
}

int32 OS_SymbolLookup(cpuaddr *SymbolAddress, const char *SymbolName)
{
    (void)SymbolName;
    if (SymbolAddress)
    {
        *SymbolAddress = 0;
    }
    return 0;
}

int32 OS_SymbolTableDump(const char *filename, size_t size_limit)
{
    (void)filename;
    (void)size_limit;
    return 0;
}

// PSP memory stubs
CFE_Status_t CFE_PSP_MemRead8(cpuaddr Address, uint8 *Value)
{
    *Value = *(uint8 *)Address;
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_MemRead16(cpuaddr Address, uint16 *Value)
{
    memcpy(Value, (void *)Address, sizeof(*Value));
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_MemRead32(cpuaddr Address, uint32 *Value)
{
    memcpy(Value, (void *)Address, sizeof(*Value));
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_MemWrite8(cpuaddr Address, uint8 Value)
{
    *(uint8 *)Address = Value;
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_MemWrite16(cpuaddr Address, uint16 Value)
{
    memcpy((void *)Address, &Value, sizeof(Value));
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_MemWrite32(cpuaddr Address, uint32 Value)
{
    memcpy((void *)Address, &Value, sizeof(Value));
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_EepromWrite8(cpuaddr Address, uint8 Value)
{
    return CFE_PSP_MemWrite8(Address, Value);
}

CFE_Status_t CFE_PSP_EepromWrite16(cpuaddr Address, uint16 Value)
{
    return CFE_PSP_MemWrite16(Address, Value);
}

CFE_Status_t CFE_PSP_EepromWrite32(cpuaddr Address, uint32 Value)
{
    return CFE_PSP_MemWrite32(Address, Value);
}

CFE_Status_t CFE_PSP_EepromWriteEnable(uint32 Bank)
{
    (void)Bank;
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_EepromWriteDisable(uint32 Bank)
{
    (void)Bank;
    return CFE_PSP_SUCCESS;
}

CFE_Status_t CFE_PSP_MemValidateRange(cpuaddr Address, size_t Size, uint32 Type)
{
    (void)Address;
    (void)Size;
    (void)Type;
    return CFE_PSP_SUCCESS;
}

// CRC stub
uint32 CFE_ES_CalculateCRC(const void *DataPtr, size_t DataLength, uint32 InputCRC, CFE_ES_CrcType_Enum_t TypeCRC)
{
    (void)TypeCRC;
    uint32 crc = InputCRC;
    const uint8_t *p = (const uint8_t *)DataPtr;
    for (size_t i = 0; i < DataLength; ++i)
    {
        crc = (crc * 33u) ^ p[i];
    }
    return crc;
}

// -----------------------------------------------------------------------------
// CFE_SB_MessageStringGet / OS_strnlen helpers
// -----------------------------------------------------------------------------

int32 CFE_SB_MessageStringGet(char *DestStringPtr, const char *SourceStringPtr, const char *DefaultString,
                              size_t DestMaxSize, size_t SourceMaxSize)
{
    const char *src = SourceStringPtr;
    size_t      i   = 0;

    if (DefaultString != NULL && (SourceMaxSize == 0 || (SourceStringPtr != NULL && SourceStringPtr[0] == '\0')))
    {
        src = DefaultString;
    }

    if (DestMaxSize == 0)
    {
        return CFE_SB_BAD_ARGUMENT;
    }

    if (src == NULL)
    {
        DestStringPtr[0] = '\0';
        return 0;
    }

    for (; i + 1 < DestMaxSize && i < SourceMaxSize && src[i] != '\0'; ++i)
    {
        DestStringPtr[i] = src[i];
    }
    DestStringPtr[i] = '\0';

    return (int32)i;
}

size_t OS_strnlen(const char *s, size_t maxlen)
{
    size_t i = 0;
    while (i < maxlen && s[i] != '\0')
    {
        ++i;
    }
    return i;
}

// -----------------------------------------------------------------------------
// CFE MSG access stubs for CCSDS command packets
// We assume the fuzzer input is a complete CCSDS TC packet as
// constructed by utils/PacketSender (SpHeader + user_data).
// SpHeader = 6-byte primary header, then user_data:
//   user_data[0] = Function Code
//   user_data[1] = checksum (ignored here)
//   user_data[2..] = arguments
// -----------------------------------------------------------------------------

static size_t g_packet_len = 0;

CFE_Status_t CFE_MSG_GetSize(const CFE_MSG_Message_t *MsgPtr, size_t *Size)
{
    (void)MsgPtr;
    if (Size)
    {
        *Size = g_packet_len;
    }
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_GetMsgId(const CFE_MSG_Message_t *MsgPtr, CFE_SB_MsgId_t *MsgId)
{
    const uint8_t *p = (const uint8_t *)MsgPtr;
    // First 2 bytes of CCSDS primary header contain version/type/SHF/APID
    uint16 raw_mid = ((uint16)p[0] << 8) | p[1];
    if (MsgId)
    {
        *MsgId = CFE_SB_ValueToMsgId(raw_mid);
    }
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_GetFcnCode(const CFE_MSG_Message_t *MsgPtr, CFE_MSG_FcnCode_t *FcnCode)
{
    const uint8_t *p = (const uint8_t *)MsgPtr;
    // Function code is first byte of user data after 6-byte primary header
    if (g_packet_len < 7)
    {
        if (FcnCode)
        {
            *FcnCode = 0;
        }
        return CFE_SUCCESS;
    }

    if (FcnCode)
    {
        *FcnCode = p[6];
    }
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_Init(CFE_MSG_Message_t *MsgPtr, CFE_SB_MsgId_t MsgId, size_t Size)
{
    (void)MsgPtr;
    (void)MsgId;
    (void)Size;
    return CFE_SUCCESS;
}

// -----------------------------------------------------------------------------
// CCSDS-level AFL harness
// -----------------------------------------------------------------------------

// Single packet buffer large enough for typical TC packets
#define MAX_PACKET_SIZE 2048
static uint8_t g_packet[MAX_PACKET_SIZE];

static void fuzz_one_ccsds(const uint8_t *data, size_t len)
{
    if (len < 8) // need at least header + fc + checksum
    {
        return;
    }

    if (len > MAX_PACKET_SIZE)
    {
        len = MAX_PACKET_SIZE;
    }

    memset(g_packet, 0, sizeof(g_packet));
    memcpy(g_packet, data, len);
    g_packet_len = len;

    // Treat the packet as an SB buffer and dispatch via MM_AppPipe.
    CFE_SB_Buffer_t *buf = (CFE_SB_Buffer_t *)g_packet;
    MM_AppPipe(buf);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    memset(&MM_AppData, 0, sizeof(MM_AppData));

    // Initialize MM once, as in a real app
    (void)MM_AppInit();

    uint8_t buf[4096];

#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(1000))
    {
        size_t len = fread(buf, 1, sizeof(buf), stdin);
        if (len == 0)
            break;
        fuzz_one_ccsds(buf, len);
    }
#else
    {
        size_t len = fread(buf, 1, sizeof(buf), stdin);
        fuzz_one_ccsds(buf, len);
    }
#endif

    return 0;
}
