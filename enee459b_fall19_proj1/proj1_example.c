#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <openssl/evp.h>
#include <capstone/capstone.h>
#include "simple_bin_proto.h"
#include "addValues.h"

// Compile me: gcc proj1_example.c -o example -lelf -lcrypto -lcapstone
// I'll drop a nice binary file on disk.

#define DISASSEMBLE_START_ADDR 0x8048b20
#define MAX_BUF_SIZE 0x1000

// From 'xxd -i'
// Alternative would be to use .incbin and some method of calculating length
extern uint8_t addValues[];
extern unsigned int addValues_len;

// Construct a structured data buffer
int make_record(uint8_t *record_buf, char *name, uint16_t machine, uint8_t *md)
{
    uint8_t *buf_ptr = record_buf;
    strncpy(((FileHeader *)record_buf)->file_name, name, sizeof(((FileHeader *)record_buf)->file_name)-1);
    buf_ptr += sizeof(FileHeader);
    ((MachineRecord *)buf_ptr)->et = MACHINE_RECORD;
    ((MachineRecord *)buf_ptr)->machine = machine;
    ((FileHeader *)record_buf)->data_length += sizeof(MachineRecord);
    buf_ptr += sizeof(MachineRecord);
    ((MD5Record *)buf_ptr)->et = MD5_RECORD;
    memcpy(&((MD5Record *)buf_ptr)->md5, md, sizeof((MD5Record *)buf_ptr)->md5);
    ((FileHeader *)record_buf)->data_length += sizeof(MD5Record);
    return sizeof(FileHeader) + ((FileHeader *)record_buf)->data_length;
}

// Example usage of libelf
uint16_t get_machine_type(int fd)
{
    Elf *e;
    GElf_Ehdr ehdr;
    uint16_t machine;

    // initialize libelf
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        errx(EXIT_FAILURE, "ELF library init failure: %s\n", elf_errmsg(-1));
    }

    // Initialize the elf object
    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        errx(EXIT_FAILURE, "ELF begin failed: %s\n", elf_errmsg(-1));
    }

    // Get the header
    if (gelf_getehdr(e, &ehdr) == NULL)
    {
        errx(EXIT_FAILURE, "getehdr failed: %s\n", elf_errmsg(-1));
    }

    printf("Machine type is 0x%x\n", ehdr.e_machine);
    machine = (uint16_t)ehdr.e_machine;
    elf_end(e);

    return machine;
}

void print_instructions(const uint8_t *buf, uint32_t addr, uint32_t len)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
        printf("ERROR: Failed to initialize engine!\n");
        return;
    }

    count = cs_disasm(handle, (unsigned char *)buf, len, addr, 0, &insn);
    if (count)
    {
        size_t j;

        for (j = 0; j < count; j++) {
            printf("%p: %s\t\t%s\n", (void *) ((uintptr_t)insn[j].address), insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);

    return;

}

int main(int argc, char **argv)
{
    int fd, i;
    uint16_t machine;
    EVP_MD_CTX *mdctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    FILE *outfile;
    uint8_t outbuf[MAX_BUF_SIZE];
    int record_size;

    // open yourself
    if ((fd = open(argv[0], O_RDONLY, 0)) < 0)
    {
        err(EXIT_FAILURE, "open %s failed\n", argv[0]);
    }

    machine = get_machine_type(fd);

    // calc MD5
    mdctx = EVP_MD_CTX_create(); // this is EVP_MD_CTX_new in newer versions
    if (0 == EVP_DigestInit_ex(mdctx, EVP_md5(), NULL))  // setup an MD5 hash
    {
        err(EXIT_FAILURE, "Failed to init MD5\n");
    }
    if (0 == EVP_DigestUpdate(mdctx, addValues, addValues_len)) // do one hash update
    {
        err(EXIT_FAILURE, "MD5 failed\n");
    }
    EVP_DigestFinal_ex(mdctx, md_value, &md_len); // finalize the hash

    printf("MD5: ");

    for (i = 0; i < md_len; i++)
    {
        printf("%02x", md_value[i]);
    }
    printf("\n");
    EVP_MD_CTX_destroy(mdctx); // this is EVP_MD_CTX_free in newer versions

    print_instructions(addValues, DISASSEMBLE_START_ADDR, addValues_len);

    close(fd);

    memset(outbuf, 0, sizeof(outbuf));

    record_size = make_record(outbuf, argv[0], machine, md_value);

    outfile = fopen("mydata.bin", "ab+");
    fwrite(outbuf, sizeof(uint8_t), record_size, outfile);
    fflush(outfile);
    fclose(outfile);

    return EXIT_SUCCESS;

}
