#ifndef SIMPLE_BIN_PROTO_H
#define SIMPLE_BIN_PROTO_H

#include <openssl/md5.h>

typedef enum
{
    MD5_RECORD,
    MACHINE_RECORD
} EntryType;

typedef struct
{
    char file_name[256];
    int data_length;
} FileHeader;

typedef struct
{
    EntryType et;
    uint16_t machine;
} MachineRecord;

typedef struct
{
    EntryType et;
    uint8_t md5[MD5_DIGEST_LENGTH];
} MD5Record;

#endif // SIMPLE_BIN_PROTO_H
