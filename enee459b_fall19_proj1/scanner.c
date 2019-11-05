#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>

#include <gelf.h>
#include <fcntl.h>
#include <err.h>
#include <stdint.h>

#include <capstone/capstone.h>
#include <openssl/rand.h>
#include "hash.h"
#include "crypto.h"

#define LOGFILE "log.txt"
#define BLOCK 4096
#define SHA1 16
#define IVSIZE 16

struct list {
    char *name;
    int cnt;
    struct list *next;
};

struct binaryinfo {
    char *name;
    uint8_t hash[SHA1];      // of .text section of file - sha1 = 16 byte hash
    struct list *insts;    // there are 1503 existing opcodes
    float e;        // entropy of .text section of file
    struct list *extern_fns;
    // TODO : add one more unique info
};

struct node {
    struct binaryinfo *b;
    struct node *next;
};

// adding/updating either instructions or extern funcs cnt in binary info lists
void update_binrecord(struct list *ml, char *op) {
    struct list *l = ml;
    // iterate over linked list of insts until we either hit the end of the 
    // list or have found the opcode in the list
    if (l->name == NULL) {
        l->name = strdup(op);
        l->cnt = 1;
    } else {
        while (l->next != NULL && (strcmp(l->name, op) != 0)) {
            l = l->next;
        }

        if (strcmp(l->name, op) == 0) {
            // increment count of item we found
            l->cnt = l->cnt + 1;
        } else {
            // add new item to the list
            struct list *nl = malloc(sizeof(struct list));
            nl->next = NULL;
            nl->name = strdup(op);
            nl->cnt = 1;
            l->next = nl;
        }
    }
}

// capstone related analysis
int analyze_cs(Elf_Data *data, struct binaryinfo **bin) {
    csh handle;
    cs_insn *insn;
    size_t cnt;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
        return -1;
    }

    cnt = cs_disasm(handle, (unsigned char *) data->d_buf,  data->d_size - 1, 0x1000, 0, &insn);
    //printf("%ld\n", cnt);
    if (cnt) {
        size_t j;
        for (j = 0; j < cnt; j++) {
            //printf("%s\n", insn[j].mnemonic);
            update_binrecord((*bin)->insts, insn[j].mnemonic); 
        }
        cs_free(insn, cnt);
    } else {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);

    return 0;
}
void printinfo(struct binaryinfo *bi) {
    int cnt;
    struct list *l = bi->insts;
    printf("SHA1 Hash of .init Section: 0x");
    for (cnt = 0; cnt < SHA1; cnt++) {
        printf("%02x", bi->hash[cnt]);
    }
    printf("\n");

    printf("---------- Instructions ----------\n");
    while (l != NULL) {
        printf("%s\t\t%d\n", l->name, l->cnt);
        l = l->next;
    }

    printf("Renyi Quadratic Entropy: %f\n", bi->e);

    l = bi->extern_fns;
    printf("------- External Functions -------\n");
    if (l->name == NULL) {
        printf("No External Functions Present\n");
    } else {
        while (l != NULL) {
            printf("%s\t\t\t%d\n", l->name, l->cnt);
            l = l->next;
            
        }
    }

}
int analyze(char *file, struct node **bl) {
    Elf *e;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    Elf_Scn *scn;
    Elf_Data *data;
    GElf_Sym sym;

    struct checksum_ctx *ctx;
    uint8_t hash[SHA1], payload[BLOCK];
    size_t shstrndx;
    char *name, *symname;

    struct node *n;
    struct binaryinfo *bin = (struct binaryinfo *) malloc(sizeof(struct binaryinfo));
    bin->name = file;
    bin->insts = (struct list *) malloc(sizeof(struct list));
    bin->extern_fns = (struct list *) malloc(sizeof(struct list));
    bin->insts->name = NULL; 
    bin->insts->next = NULL;
    bin->extern_fns->name = NULL;
    bin->extern_fns->next = NULL;
    bin->e = 0;

    int i, cnt, fd = open(file, O_RDONLY, 0);

    if (fd < 0) {
        printf("Error while opening %s\n", file);
        exit(1);
    }

    if (elf_version(EV_CURRENT) == EV_NONE ) {
        printf("lib init failed");
        exit(1);
    }

    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        printf("elf begin failed");
        exit(1);
    }

    if (gelf_getehdr(e, &ehdr) == NULL ) {
        printf("The given file is not an ELF file.\n");
        exit(1);
    }

    if (elf_kind(e) != ELF_K_ELF || gelf_getclass(e) != ELFCLASS64 || (
                ehdr.e_machine != 0x03 && ehdr.e_machine !=0x3E)) {
        printf("The file is not an ELF-64 file for an intel architecture\n");
        exit(1);
    }

    if (elf_getshdrstrndx(e, &shstrndx) != 0) {
        exit(1);
    }

    /* loop through all of the sections in the ELF file */
    scn = NULL;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            exit(1);
        }

        name = elf_strptr(e, shstrndx, shdr.sh_name);
        printf("name : %s\n", name);        

        // section is a symbol table
        if (shdr.sh_type == SHT_SYMTAB) {
            data = NULL;
            elf_getdata(scn, data);
            //buff = malloc(data->d_size);
            //buff = data->d_buf;

            // print the symbol names 
            cnt = shdr.sh_size / shdr.sh_entsize;
            for (i = 0; i < cnt; ++i) {
                gelf_getsym(data, i, &sym);
                symname = elf_strptr(e, shdr.sh_link, sym.st_name);
                if (symname != NULL) {
                    printf("sn: %s\n", symname);
                    update_binrecord(bin->extern_fns, symname);
                }
            }
        }

        // .text section 
        if (strcmp(name, ".text") == 0) {
            data = elf_getdata(scn, NULL);
            ctx = checksum_create(NULL, 0);    

            // hash in BLOCK size chunks
            // TODO disassem just .text or all sections? might have issues
            lseek(fd,  shdr.sh_offset, SEEK_SET);
            for (cnt = 0; (cnt + BLOCK) < shdr.sh_size; cnt += BLOCK) {
                read(fd, payload, BLOCK); 
                checksum_update(ctx, payload);
            }

            read(fd, payload, (shdr.sh_size - cnt)); 
            checksum_finish(ctx, payload, (shdr.sh_size - cnt), hash);
            memcpy(bin->hash, hash, SHA1); 

            analyze_cs(data, &bin); // TODO disassem just .text or all sections? might have issues
        }
    }

    // print info about the binary file we collected
    printinfo(bin);

    // add the binary to bl (append to head of list)
    if ((*bl)->b == NULL) {
        // just reassign
        (*bl)->b = bin;
    } else {
        n = (struct node *) malloc(sizeof(struct node));
        n->b = bin;
        n->next = (*bl);
        (*bl) = n;
    }
    elf_end(e);
    close(fd);
    return 0;
}

// return 1 on success, 0 on failure
int lookup(char *file, struct node *bl) {
    while (bl != NULL && bl->b != NULL) {
        if (strcmp(bl->b->name, file) == 0) {
            printinfo(bl->b);
            return 1;
        }
    }
    printf("No record of %s. Could not lookup\n", file);
    return 0;
}

// return 1 on success, 0 on failure
int delete_record(char *file, struct node **bl) {
    struct node *prev, *be = (*bl);

    // nothing is in the bl yet, aka nothing to delete
    if ((*bl)->b == NULL) {
        printf("Nothing in the list, therefore nothing to delete. Try adding some records first!\n");
        return 0;
    }


    // if head holds the value, reassign head
    if (be != NULL && (strcmp(be->b->name, file) == 0)) {
        (*bl) = be->next;
        free(be);
        return 1;
    }

    while (be != NULL && (strcmp(be->b->name, file) != 0)) {
        prev = be;
        be = be->next;
    }

    if (be == NULL) {
        printf("attempting to delete something that does not exist. Nothing will be modified.\n");
        return 0;
    }

    prev->next = be->next;
    free(be);
    return 1;
}

/* WRITE FORMAT
 *
 * iv (16 bytes)
 * for every binary in lb:
 *      n bytes in bin name (1)
 *      bin name (n)
 *      sha1 hash (16)
 *      entropy (4)
 *      number of opcodes (2)
 *      for every opcode:
 *              m bytes in opcode name (1)
 *              opcode name (m)
 *              opcode count (4)
 *      number of extern fns (2)
 *      for every extern fn:
 *              k bytes in fn name (1)
 *              fn name (k)
 *              fn count (4)
 *
 */ 
void write_and_exit(struct node *bl, uint8_t *key) {
    unsigned char *ct, iv[IVSIZE], *buff = malloc(sizeof(struct binaryinfo));
    int num_bins = 1, len, i = 0, j = 0, k;
    struct list *l;
    FILE *fp;

    // write iv to the file for futre decryption
    RAND_bytes(iv, IVSIZE);
    fp = fopen(LOGFILE, "w");
    fwrite(iv, IVSIZE, 1, fp);

    // add every bl entry to the write buff
    while (bl != NULL) {
        len = strlen(bl->b->name);
        buff = realloc(buff, i+(len+6+SHA1)); // 1 + len + SHA1 + 4 + 

        // add the strlen of the name (1 byte) and the name to the buff
        buff[i] = len;
        memcpy(buff+(i+1), bl->b->name, len);

        // add the sha1 hash (16 bytes)
        memcpy(buff+(i+1+len), bl->b->hash, SHA1);

        // add entropy (4 bytes)
        memcpy(buff+i+1+len+SHA1, (float *) &(bl->b->e), 4);

        i += 5+len+SHA1;
        k = i++; // place holder for number of opcodes

        // add strlen(opcode), opcode, and opcode count for each binary info struct
        l = bl->b->insts;
        while (l != NULL) {
            len = strlen(l->name);
            buff = realloc(buff, ((i+len+6) * num_bins)); // allocate space for (2 + len + 4) bits

            memcpy(buff+i, &len, 2);
            memcpy(buff+(i+2), l->name, len);
            memcpy(buff+(i+2+len), &(l->cnt), 4);

            i += len+6; // strlen (2) + opcode str (len) + opcode cnt (4)
            j++;
            l = l->next;
        }

        buff[k] = j;    // write how many opcodes there are to process before opcode info
        j = 0;          // reset j
        buff = realloc(buff, i+1);
        k = i++;          // placeholder for number of external functions

        // add strlen(extern fn name), extern fn_name, and count for each binary info struct
        l = bl->b->extern_fns;
        if (l->name) {
            while (l != NULL) {
                len = strlen(l->name);
                buff = realloc(buff, ((i+len+6) * num_bins)); // allocate space for (2 + len + 4) bits

                memcpy(buff+(i), &len, 2);
                memcpy(buff+(i+2), l->name, len);
                memcpy(buff+(i+2+len), &(l->cnt), 4);

                i += len+6;
                j++;
                l = l->next;
            }
        }

        // write how many opcodes there are to process before opcode info
        buff[k] = j;

        // repeat for each binaryinfo struct in the program
        bl = bl->next;
    }

    ct = malloc(((int) (i+IVSIZE)) + 16);
    encrypt(buff, i, key, iv, ct);
    fwrite(ct, i, 1, fp);

    free(ct);
    free(bl);
    exit(1);
}

/* READ FORMAT
 * iv (16 bytes)
 * 
 * for every binary in lb:
 *      n bytes in bin name (1)
 *      bin name (n)
 *      sha1 hash (16)
 *      entropy (4)
 *      number of opcodes (2)
 *      for every opcode:
 *              m bytes in opcode name (1)
 *              opcode name (m)
 *              opcode cont (4)
 *      number of extern fns (2)
 *      for every extern fn:
 *              k bytes in fn name (1)
 *              fn name (k)
 *              fn count (4)
 */

// bl->b and bl->next are passed in NULL
void load_log(struct node **bl, uint8_t *key) {
    int i, e, namelen, fs, cnt, num;
    unsigned char iv[IVSIZE], hash[SHA1];
    char *name = NULL; 
    FILE *fp;

    // if the log file does not exist then do nothing
    if ((fp = fopen(LOGFILE, "r")) == NULL) {
        return;
    }

    fseek(fp, 0, SEEK_END);
    fs = ftell(fp) - SHA1;
    fseek(fp, 0, SEEK_SET); // reset

    // if the file is empty then do nothing
    if (fs == 0) {
        return;
    }

    unsigned char ct[fs], pt[fs];

    // first read the iv to decrypt
    fread(iv, SHA1, 1, fp);
    fs -= SHA1;
    // then read in the rest of the file and decrypt
    fread(ct, fs, 1, fp);
    if (decrypt(ct, fs, key, iv, pt) <= 0) {
        return;
    }

    while (fs > 0) {
        // add each entry to the head of the binary info linked list
        struct node *new_node = (struct node *) malloc(sizeof(struct node));
        new_node->b = (struct binaryinfo *) malloc(sizeof(struct binaryinfo));

        // read in binary file name
        fread(&namelen, 1, 1, fp);
        fread(name, namelen, 1, fp);
        new_node->b->name = name;

        fread(hash, SHA1, 1, fp);
        memcpy(new_node->b->hash, hash, SHA1);

        fread(&e, 4, 1, fp);
        new_node->b->e = e;

        // read in num instructions
        fread(&num, 2, 1, fp);
        new_node->b->insts = (struct list *) malloc(sizeof(struct list) * num);
        for (i = 0; i < num; i++) {
            struct list *new_entry = (struct list *) malloc(sizeof(struct list));
            fread(&namelen, 1, 1, fp);
            fread(name, namelen, 1, fp);
            fread(&cnt, 4, 1, fp);
            new_entry->name = name;
            new_entry->cnt = cnt;

            // if inst list is empty, modify the head
            if (new_node->b->insts->name == NULL) {
                new_node->b->insts->name = name;
                new_node->b->insts->cnt = cnt;
            } else {
                // just append to the head of the list
                new_entry->next = new_node->b->insts;
                new_node->b->insts = new_entry;
            }
        }

        // read in num functions 
        fread(&num, 2, 1, fp);
        new_node->b->extern_fns = (struct list *) malloc(sizeof(struct list) * num);
        for (i = 0; i < num; i++) {
            struct list *new_entry = (struct list *) malloc(sizeof(struct list));
            fread(&namelen, 1, 1, fp);
            fread(name, namelen, 1, fp);
            fread(&cnt, 4, 1, fp);
            new_entry->name = name;
            new_entry->cnt = cnt;

            // if inst list is empty, modify the head
            if (new_node->b->extern_fns->name == NULL) {
                new_node->b->extern_fns->name = name;
                new_node->b->extern_fns->cnt = cnt;
            } else {
                // just append to the head of the list
                new_entry->next = new_node->b->extern_fns;
                new_node->b->extern_fns = new_entry;
            }
        }

        // if (*bl) has no entries, make the new node's information the head's info
        if ((*bl)->b == NULL) {
            (*bl)->b = new_node->b;
        } else { // else just append to the head of the list
            new_node->next = (*bl);
            (*bl) = new_node;
        }
    }
}

/* input options
 * log informaiton on a given binary
 * retrieve and display info about binaries in the log
 * auth mech to retrieve and display info about a binary
 *      delete records if superuser (sudo)
 */
int main(int argc, char *argv[]) {
    // binary scanner should be run with a binary file as an argument
    int i = 0;
    char filename[256];
    unsigned char key[32];
    struct node *bl = malloc(sizeof(struct node));
    bl->b = NULL;
    bl->next = NULL;

    if ( (argc != 3 && argc != 4) || strcmp(argv[i+1], "-k") != 0 || argv[i+2] == NULL) {
        printf("Usage: ./scanner -k <key>\n");
        exit(1);
    }

    strcpy( (char *) key, argv[i+2]);
    printf("256 bit key provided: %s\n", key);

    // load existing log file
    if (access(LOGFILE, R_OK) ) {
        load_log(&bl, key);
    }

    // continuous service, waits on user input. must exit via options to quit.
    while (1) {
        printf("Opions:\n(1) analyze binary file\n(2) retrieve previously analyzed binary information\n(3) delete log - must be sudo\n(4) exit\n");
        switch (getchar()) {
            case '1':
                printf("Enter file name to analyze: ");
                scanf("%s", filename);
                analyze(filename, &bl);
                write_and_exit(bl, key);
                break;
            case '2':
                printf("Enter file name to lookup:");
                scanf("%s", filename);
                if (lookup(filename, bl)) {
                    write_and_exit(bl, key);
                } else { exit(1); }
                break;
            case '3':
                if (geteuid() == 0) {
                    printf("Enter binary record to delete:");
                    scanf("%s", filename);
                    if (delete_record(filename, &bl)) {
                        write_and_exit(bl, key);
                    } else { exit(1); }
                } else {
                    printf("Must be superuser in order to delete a file\n");
                    exit(1);
                }
                break;
            case '4':
                exit(1);
                break;
            default: 
                printf("Not a valid option. Try again.\n");
                break;
        }
    }
    return 0;
}