#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>

#include <gelf.h>
#include <fcntl.h>
#include <err.h>
#include <stdint.h>

#include <capstone/capstone.h>
#include <openssl/rand.h>
#include "hash.h"
#include "crypto.h"
//#include "incrementByFour.h"

#define LOGFILE "log.txt"
#define BLOCK 4096
#define SHA1 16
#define KEYSIZE 32
#define IVSIZE 16
#define PASS "elf_begin" // to confuse smart ppl who thought to use strings hehe

//extern int incrementByFour(int n);

struct node {                                                                   
    void *data;         // will either be binary info or pair or cred
    struct node *next;                                                          
};                                                                               

struct list {                                                                   
    int size;                                                                   
    struct node *head;                                                          
};                                                                              

struct fndata {
    char *name;
    char *addr;
    int cnt;
};

struct pair {                                                                   
    char *name;                                                                 
    int cnt;                                                                    
};             

struct cred {
    char *user;
    char *pass;
};

struct binaryinfo {
    char *uid;
    char *name;                                                                 
    uint8_t hash[SHA1];         // of .text section of file - sha1 = 16 byte hash  
    struct list *insts;         // there are 1503 existing opcodes                   
    float e;                    // entropy of .text section of file                         
    struct list *extern_fns;                                                    
    struct list *sections;                                                      
};               

// assembly function
//extern unsigned char incrementByFour[];

// --------------- linked list functions ---------------
// push new_data to head of the list
void push(struct list *l, void *new_data) {
    struct node **head_ref = &(l->head);
    struct node* new_node = (struct node*) malloc(sizeof(struct node)); 
    new_node->data  = new_data; 
    new_node->next = (*head_ref); 
    (*head_ref)    = new_node; 
    l->size += 1;
} 

// lookup based off of name, return reference to node's data
struct cred *lookup_cred(struct node* head, char *name) {
    struct node* current = head;  // Initialize current
    struct cred *x;
    while (current != NULL) {
        x = current->data;
        if (x->user && strcmp(x->user, name) == 0) {
            return current->data;
        }
        current = current->next;
    }
    return NULL;
}

struct binaryinfo *lookup_bin(struct node* head, char *name) {
    struct node* current = head;  // Initialize current
    struct binaryinfo *x;
    while (current != NULL) {
        x = current->data;
        if (strcmp(x->name, name) == 0) {
            return current->data;
        }
        current = current->next;
    }
    return NULL;
}

struct pair *lookup_pair(struct node* head, char *name) {
    struct node* current = head;  // Initialize current
    struct pair *x;
    while (current != NULL) {
        x = current->data;
        if (strncmp(x->name, name, strlen(name)) == 0) {
            return current->data;
        }
        current = current->next;
    }
    return NULL;
}

struct fndata *lookup_fn(struct node* head, char *addr) {
    struct node* current = head;  // Initialize current
    struct fndata *x;
    while (current != NULL) {
        x = current->data;
        if (strcmp(x->addr, addr) == 0) {
            return current->data;
        }
        current = current->next;
    }
    return NULL;
}

// delete node given the name
void delete(struct node **head_ref, char *name)  { 
    // Store head node 
    struct node* temp = *head_ref, *prev; 

    // If head node itself holds the key to be deleted 
    struct binaryinfo *x = temp->data;                               
    if (temp != NULL && (strcmp(name, x->name) == 0)) { 
        *head_ref = temp->next;   // Changed head 
        free(temp);               // free old head 
        return; 
    } 

    // Search for the key to be deleted, keep track of the 
    // previous node as we need to change 'prev->next' 

    while (temp != NULL && (strcmp(name, x->name) == 0))  { 
        prev = temp; 
        temp = temp->next; 
        x = temp->data;
    } 

    // If key was not present in linked list 
    if (temp == NULL) return; 

    // Unlink the node from linked list 
    prev->next = temp->next; 

    free(temp);  // Free memory 
}
// ------------------------------------------------

// capstone related analysis
int disassem_insts(Elf *e, struct binaryinfo *bin, Elf_Data *rela_data, 
        Elf_Data *data, Elf_Data *data_got, Elf_Data *data_dsym, 
        GElf_Shdr *shdr_got, GElf_Shdr *shdr_dsym, GElf_Shdr *shdr_rela) {
    
    csh handle;
    cs_insn *insn;
    size_t i;
    char addr[256], *fn_name;
    Elf64_Sym sym; 
    Elf64_Rela rela_entry;
    struct pair *p;
    struct fndata *f;
    int got_offset, call_addr, sym_idx, entries = 0;
    
    if (shdr_rela->sh_entsize != 0) {
        entries = shdr_rela->sh_size / shdr_rela->sh_entsize;
    } 

    for (i=0; i < entries; i++) {
        // get call addr for entry
        rela_entry = ((Elf64_Rela *) (rela_data->d_buf))[i];
        got_offset = (rela_entry.r_offset - shdr_got->sh_addr);
        call_addr = ((int*)(data_got->d_buf))[got_offset];
        //printf("%x\n", call_addr);
        sprintf(addr, "0x%x", call_addr);

        // get the name!
        sym_idx = rela_entry.r_info >> 32;
        gelf_getsym(data_dsym, sym_idx, &sym);
        fn_name = elf_strptr(e, shdr_dsym->sh_link, sym.st_name);   

        //printf("name: %s, addr: %x\n", fn_name, call_addr);
        // initialize fndata list with counts of 0
        f = (struct fndata *) malloc(sizeof(struct fndata));
        f->name = strdup(fn_name);
        f->addr = strdup(addr);
        f->cnt = 0;
        push(bin->extern_fns, f);
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
        return -1;
    }

    i = cs_disasm(handle, (unsigned char *) data->d_buf,  data->d_size - 1, 0x1000, 0, &insn);
    if (i) {
        size_t j;
        for (j = 0; j < i; j++) {
            //printf("inst: %s\t%s\n", insn[j].mnemonic, insn[j].op_str);
/*
            if ((strcmp(insn[j].mnemonic, "call") == 0)) {
                printf("%s %s\n", insn[j].mnemonic, insn[j].op_str);
            }
*/
            if ((strcmp(insn[j].mnemonic, "call") == 0) &&
                (f = lookup_fn(bin->extern_fns->head, insn[j].op_str)) != NULL) {
                f->cnt += 1;
            } 

            if ((bin->insts->head == NULL) || 
                    ((p = lookup_pair(bin->insts->head, insn[j].mnemonic)) == NULL)) {
                p = (struct pair *) malloc(sizeof(struct pair));
                p->cnt = 1;
                p->name = strdup(insn[j].mnemonic);
                push(bin->insts, p);
            } else {
                p->cnt += 1;
            }
        
        }
        cs_free(insn, i);
    } else {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);

    return 0;
}

void printinfo(struct binaryinfo *bi) {
    int cnt;
    struct node *l = bi->insts->head;
    struct pair *p;
    struct fndata *f;

    printf("SHA1 Hash of .init Section: 0x");
    for (cnt = 0; cnt < SHA1; cnt++) {
        printf("%02x", bi->hash[cnt]);
    }
    printf("\n");

    printf("---------- Instructions ----------\n");
    while (l != NULL) {
        p = l->data;
        printf("%s\t\t%d\n", p->name, p->cnt);
        l = l->next;
    }

    printf("Renyi Quadratic Entropy: %f\n", bi->e);

    l = bi->extern_fns->head;
    printf("------- External Functions -------\n");
    if (l == NULL) {
        printf("No External Functions Present\n");
    } else {
        while (l != NULL) {
            f = l->data;
            printf("%s\t\t\t%d\n", f->name, f->cnt);
            l = l->next;
        }
    }
    
    printf("------- Section Information -------\n");
    l = bi->sections->head;
    while (l != NULL) {
        p = l->data;
        printf("%s\t\tsize in bytes: %d\n", p->name, p->cnt);
        l = l->next;
    }
}

float intlog(float base, float x) {
    return (float)(logf(x) / logf(base));
}

float calc_entropy(Elf_Data *data) {
    int bytes[256], i;
    uint8_t j;
    float p, sum = 0;

    // entropy calculation array, initialized to 0
    for (i = 0; i < 256; i++) {
        bytes[i] = 0;
    }

    // keep track of how often each byte occurs 
    for (i = 0; i < data->d_size; i++) {
        j = ((unsigned char *) (data->d_buf))[i];
        bytes[j] += 1;
    }

    // sum each probability sqaured
    for (i = 0; i < 256; i++) {
        p = ((float) bytes[i] / data->d_size);
        sum += (p*p);
    }

    // e = -logb(sum)
    return (intlog((float)256, sum) * -1);
}

int analyze(char *file, char *user, struct list *bl) {
    Elf *e;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr, shdr_dsym, shdr_got, shdr_rela;
    Elf_Scn *scn;
    Elf_Data *rela_data, *txt_data, *dsym_data, *got_data;

    struct checksum_ctx *ctx;
    uint8_t hash[SHA1], payload[BLOCK];
    size_t shstrndx;
    char *name;
    int cnt, fd;
    
    struct pair *ps;

    // binary information struct
    struct binaryinfo *bin = (struct binaryinfo *) malloc(sizeof(struct binaryinfo));
    bin->name = file;
    bin->uid = user;
    bin->insts = (struct list *) malloc(sizeof(struct list));
    bin->extern_fns = (struct list *) malloc(sizeof(struct list));
    bin->sections = (struct list *) malloc(sizeof(struct list));
    bin->insts->head = NULL; 
    bin->insts->size = 0;
    bin->extern_fns->head = NULL;
    bin->extern_fns->size = 0;
    bin->sections->head = NULL;
    bin->sections->size = 0;
    bin->e = 0;

    // list of strings, duplicates allowed
    struct list *fns = (struct list *) malloc(sizeof(struct list));
    fns->size = 0;
    fns->head = NULL;

    fd = open(file, O_RDONLY, 0);

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

        ps = malloc(sizeof(struct pair));
        ps->name = strdup(name);
        ps->cnt = shdr.sh_size;
        push(bin->sections, ps);

        if (strcmp(name, ".dynsym") == 0) {
            shdr_dsym = shdr;
            dsym_data = elf_getdata(scn, NULL);            
        }

        if (strcmp(name, ".rela.plt") == 0) {
            shdr_rela = shdr;
            rela_data = elf_getdata(scn, NULL);            
        }

        if (strcmp(name, ".got") == 0) {
            shdr_got = shdr;
            got_data = elf_getdata(scn, NULL);            
        }

        // .text section 
        if (strcmp(name, ".text") == 0) {
            txt_data = elf_getdata(scn, NULL);

            // for each individual byte, calc entropy (not efficient but oh whale)
            bin->e = calc_entropy(txt_data);

            // hash .text in BLOCK size chunks
            ctx = checksum_create(NULL, 0);    
            lseek(fd,  shdr.sh_offset, SEEK_SET);
            for (cnt = 0; (cnt + BLOCK) < shdr.sh_size; cnt += BLOCK) {
                read(fd, payload, BLOCK); 
                checksum_update(ctx, payload);
            }
            read(fd, payload, (shdr.sh_size - cnt)); 
            checksum_finish(ctx, payload, (shdr.sh_size - cnt), hash);
            memcpy(bin->hash, hash, SHA1); 
        }
    }

    // disassemble with capstone
    disassem_insts(e, bin, rela_data, txt_data, got_data, dsym_data, &shdr_got, &shdr_dsym, &shdr_rela);
    // print info about the binary file we collected
    printinfo(bin);
    // add this info to the binary file list
    push(bl, bin);

    elf_end(e);
    close(fd);
    return 0;
}

int invalid_creds(char *uid, char *password, struct list *creds) {
    struct cred *c = lookup_cred(creds->head, uid);
    if (c == NULL) {
        // new user! add them to the user list
        struct cred *nc = (struct cred *) malloc(sizeof(struct cred));
        nc->user = uid;
        nc->pass = password;
        push(creds, nc);
    } else {
        // preexisting user: check their password!
        if (strcmp(c->pass, password) != 0) {
            return 1;
        }
    }
    return 0;
}


void store(char *file, struct list *bl, struct list *creds) {

    FILE *fp = fopen(LOGFILE, "w");
    unsigned char *pt, *ct, key[KEYSIZE], iv[IVSIZE];
    
    int bin_name_len, uid_len, i, idx, userlen, passlen, es, len;
    struct node *curr = creds->head;
  
    struct binaryinfo *b;
    struct pair *p;
    struct fndata *f;
    struct node *n;
    struct cred *c;

    // write encryption info
    RAND_bytes(key, KEYSIZE);
    RAND_bytes(iv, IVSIZE);
    fwrite(key, KEYSIZE, 1, fp);
    fwrite(iv, IVSIZE, 1, fp);

    idx = 0;

    // write user information
    pt = malloc(1);
    pt[idx++] = creds->size;

    for (i = 0; i < creds->size; i++) {
        c = curr->data;
        userlen = strlen(c->user);
        passlen = strlen(c->pass);
        pt = realloc(pt, idx+userlen+passlen+2);

        pt[idx++] = userlen;
        memcpy(pt+idx, c->user, userlen);
        idx += userlen;

        pt[idx++] = passlen;
        memcpy(pt+idx, c->pass, passlen);
        idx += passlen;

        curr = curr->next;
    }

    // read in binary information

    pt = realloc(pt, idx+1);
    pt[idx++] = bl->size;

    curr = bl->head;
    for (i = 0; i < bl->size; i++) {
        b = curr->data;
        uid_len = strlen(b->uid);
        bin_name_len = strlen(b->name);
        pt = realloc(pt, idx+uid_len+bin_name_len+SHA1+10);

        pt[idx++] = uid_len;
        memcpy(pt+idx, b->uid, uid_len);
        idx += uid_len;

        pt[idx++] = bin_name_len;
        memcpy(pt+idx, b->name, bin_name_len);
        idx += bin_name_len;

        memcpy(pt+idx, &(b->hash), SHA1);
        idx+=SHA1;

        memcpy(pt+idx, &(b->e), 4);
        idx += 4;
        //idx = incrementByFour(idx);

        // opcode info                                                          
        memcpy(pt+idx, &(b->insts->size), 4);
        idx += 4;

        n = b->insts->head;
        for (i = 0; i < b->insts->size; i++) {
            p = n->data;
            len = strlen(p->name);
            pt = realloc(pt, idx+len+5);
            pt[idx++] = len;
            memcpy(pt+idx, p->name, len);
            idx += len;       
            memcpy(pt+idx, &(p->cnt), 4);                                        
            idx += 4;        
            n = n->next;
        }    

        // extern fn info
        pt = realloc(pt, idx+4);
        memcpy(pt+idx, &(b->extern_fns->size), 4);
        idx+=4;

        n = b->extern_fns->head;
        for (i = 0; i < b->extern_fns->size; i++) {
            f = n->data;
            len = strlen(f->name);                                        
            pt = realloc(pt, idx+len+5);                                        
            pt[idx++] = len;                                                    
            memcpy(pt+idx, f->name, len);                                 
            idx += len;                                                           
            memcpy(pt+idx, &(f->cnt), 4);                                        
            idx += 4;                                                             
            n = n->next; 
        }

        // sections info
        pt = realloc(pt, idx+4);                                                
        memcpy(pt+idx, &(b->sections->size), 4);                               
        idx += 4;  
        
        n = b->sections->head;
        for (i = 0; i < b->sections->size; i++) {
            p = (n->data);
            len = strlen(p->name);                                        
            pt = realloc(pt, idx+len+5);                                        
            pt[idx++] = len;                                                    
            memcpy(pt+idx, p->name, len);                                 
            idx += len;      
            memcpy(pt+idx, &(p->cnt), 4);                                        
            idx += 4;                                                             
            n = n->next; 
        }

        curr = curr->next;
    }

    // ecrypt and append to file
    ct = malloc(idx+16);
    es = encrypt(pt, idx, key, iv, ct);
    fwrite(ct, es, 1, fp);
    free(pt);
    free(ct);
}


/*
 * bl = list of binary information structs we are going to fill
 * creds = list of user/pass combos we are going to fill
 */
void load(struct list *bl, struct list *creds) {
    FILE *fp;
    uint8_t key[KEYSIZE], iv[IVSIZE];
    int passlen, userlen, fs, num_users, i, idx, uid_len;
    struct pair *p;
    int num_insts, inst_len;
    int num_fns, fn_len;
    int num_sections, section_name_len, section_size;
    struct fndata *f;

    // if the log file does not exist then do nothing                           
    if ((fp = fopen(LOGFILE, "r")) == NULL) {                                   
        printf("log file not present!\n");
        return;
    } 

    // get file size
    fseek(fp, 0L, SEEK_END);
    fs = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    fread(key, KEYSIZE, 1, fp);
    fread(iv, IVSIZE, 1, fp);
    fs -= KEYSIZE+IVSIZE;

    uint8_t ct[fs], pt[fs];

    fread(ct, fs, 1, fp);
    if ((fs = decrypt(ct, fs, key, iv, pt)) <= 0) {
        return;
    }

    idx = 0;

    // read in user information
    num_users = pt[idx++];
    for (i = 0; i < num_users; i++) {
        struct cred *c = (struct cred *) malloc(sizeof(struct cred));

        userlen = pt[idx++];           
        c->user = strndup((char*) pt+idx, userlen);
        idx += userlen;
        passlen = pt[idx++];
        c->pass = strndup((char*) pt+idx, passlen);
        idx += passlen;

        push(creds, c);
    }

    // read in binary information
    int num_binaries, bin_name_len;
    num_binaries = pt[idx++];
    for (i = 0; i < num_binaries; i++) {
        // create bininfo obj with this information and add it to bl
        struct binaryinfo *bin = (struct binaryinfo *) malloc(sizeof(struct binaryinfo));

        uid_len = pt[idx++];
        bin->uid = strndup((char*) pt+idx, uid_len);
        idx += uid_len;

        bin_name_len = pt[idx++];
        bin->name = strndup((char*) pt+idx, bin_name_len);
        idx += bin_name_len;

        memcpy(&(bin->hash), pt+idx, SHA1);
        idx += SHA1;

        memcpy(&(bin->e), pt+idx, 4);
        idx += 4;

        // opcode info
        bin->insts = (struct list *) malloc(sizeof(struct list));
        bin->insts->head = NULL;
        bin->insts->size = 0;

        memcpy(&num_insts, pt+idx, 4);
        idx += 4;
        for (i = 0; i < num_insts; i++) {
            p = (struct pair *) malloc(sizeof(struct pair));
            inst_len = pt[idx++];
            p->name = strndup((char*) pt+idx, inst_len);
            idx += inst_len;
            p->cnt = *((int*)(pt+idx));
            idx+=4;

            push(bin->insts, p);
        }

        // extern fn info
        bin->extern_fns = (struct list *) malloc(sizeof(struct list));
        bin->extern_fns->head = NULL;
        bin->extern_fns->size = 0;

        memcpy(&num_fns, pt+idx, 4);
        idx += 4;
        for (i = 0; i < num_fns; i++) {
            f = (struct fndata *) malloc(sizeof(struct fndata));
            fn_len = pt[idx++];
            f->name = strndup((char*) pt+idx, fn_len);
            idx += fn_len;
            f->cnt = *((int*)(pt+idx));
            idx += 4;
            f->addr = NULL;
            push(bin->extern_fns, f);
        }

        // section info
        bin->sections = (struct list *) malloc(sizeof(struct list));
        bin->sections->head = NULL;
        bin->sections->size = 0;

        memcpy(&num_sections, pt+idx, 4);
        idx += 4;
        for (i = 0; i < num_sections; i++) {
            p = (struct pair *) malloc(sizeof(struct pair));
            section_name_len = pt[idx++];
            p->name = strndup((char*) pt+idx, section_name_len);
            idx += fn_len;
            p->cnt = *((int*)pt+idx);
            memcpy(&section_size, pt+idx, 4);
            idx += 4;
            push(bin->sections, p);
        }

        //push new binary info struct to bl
        push(bl, bin);
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
    int opt, index, admin = 0;
    char *passwd = NULL, *task = NULL, *file = NULL, *uid = NULL;
    struct binaryinfo *b;

    struct list *bl = malloc(sizeof(struct list));
    bl->size = 0;
    bl->head = NULL;

    struct list *creds = malloc(sizeof(struct list));
    creds->size = 0;
    creds->head = NULL;

    // TODO: check username and password len <= 255
    // argument parsing with getopt
    while((opt = getopt(argc, argv, "au:p:f:t:")) != -1) {
        switch (opt) {
            case 'a':   // admin
                admin = 1;
                break;
            case 'u':   // user
                uid = optarg;
                break;
            case 'p':   // passwd
                passwd = optarg;
                break;
            case 'f':   // binary file name 
                file = optarg;
                break;
            case 't':   // task : 
                task = optarg;
                break;
            case ':':
                   printf("option needs a value\n");
                   break;
            case '?':
                   if (optopt == 'u' || optopt == 'p' || optopt == 'f' || optopt == 't') {
                       fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                   }  else if (isprint(optopt)) {
                       fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                   } else {
                       fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                   }
                   return -1;
            default:
                   exit(1);
        }
    }
    //printf("a=%d, u=%s, p=%s, f=%s, t=%s\n", admin, uid, passwd, file, task);

    for (index = optind; index < argc; index++) {
        printf("Non-option argument %s\n", argv[index]);
    }

    if (passwd == NULL || file == NULL || task == NULL) {
        printf("Usage: ./binscan [-u <username> | -a] -p <password> -f <file> -t <type>\n");
        exit(1);
    }

    if (admin && strcmp(passwd, PASS) != 0) {
        printf("Incorrect Admin Password. Try Again!\n");
        exit(1);
    } 

    if (admin) {
        uid = "admin";
    }

    // read in file
    load(bl, creds);

    // check credentials for current user
    if (invalid_creds(uid, passwd, creds)) {
        printf("Incorrect password for %s\n", uid);
        exit(1);
    }

    // analyze binary file
    if (strcmp(task, "analyze") == 0) {
        analyze(file, uid, bl);

    // lookup binary file
    } else if (strcmp(task, "lookup") == 0) {
        b = lookup_bin(bl->head, file);
        if (strcmp(b->uid, uid) == 0 || admin) {
            printinfo(b);
        } else {
            printf("Sorry! This binary does not belong to you.\n");
        }
        exit(1); // no need to read from file, just reading

    // delete an entry 
    } else if (strcmp(task, "delete") == 0) {
        if (admin) {
            delete(&(bl->head), file);
        } else {
            printf("Only Admins can delete binary records\n");
            exit(1);
        }

    // invalid task
    } else {
        printf("possible tasks are lookup, delete, and analyze. Try again!");
        exit(1);
    }

    store(file, bl, creds);
    return 0;
}