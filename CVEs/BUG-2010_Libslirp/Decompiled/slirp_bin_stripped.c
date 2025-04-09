typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    qword;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct NoteGnuPropertyElement_4 NoteGnuPropertyElement_4, *PNoteGnuPropertyElement_4;

struct NoteGnuPropertyElement_4 {
    dword prType;
    dword prDatasz;
    byte data[4];
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef ushort sa_family_t;

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef long __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[20];
};

struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct stat stat, *Pstat;

typedef ulong __dev_t;

typedef ulong __ino_t;

typedef ulong __nlink_t;

typedef uint __mode_t;

typedef uint __uid_t;

typedef uint __gid_t;

typedef long __blksize_t;

typedef long __blkcnt_t;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

struct stat {
    __dev_t st_dev;
    __ino_t st_ino;
    __nlink_t st_nlink;
    __mode_t st_mode;
    __uid_t st_uid;
    __gid_t st_gid;
    int __pad0;
    __dev_t st_rdev;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    long __unused[3];
};

typedef struct in_addr in_addr, *Pin_addr;

typedef uint uint32_t;

typedef uint32_t in_addr_t;

struct in_addr {
    in_addr_t s_addr;
};

typedef struct _IO_FILE FILE;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

typedef uint __socklen_t;

typedef __socklen_t socklen_t;

typedef long __ssize_t;

typedef __ssize_t ssize_t;

typedef int __pid_t;

typedef int (*__compar_fn_t)(void *, void *);

typedef enum Elf_ProgramHeaderType {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482
} Elf_ProgramHeaderType;

typedef struct Elf64_Dyn Elf64_Dyn, *PElf64_Dyn;

typedef enum Elf64_DynTag {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf64_DynTag;

struct Elf64_Dyn {
    enum Elf64_DynTag d_tag;
    qword d_val;
};

typedef struct Elf64_Rela Elf64_Rela, *PElf64_Rela;

struct Elf64_Rela {
    qword r_offset; // location to apply the relocation action
    qword r_info; // the symbol table index and the type of relocation
    qword r_addend; // a constant addend used to compute the relocatable field value
};

typedef struct Elf64_Shdr Elf64_Shdr, *PElf64_Shdr;

typedef enum Elf_SectionHeaderType {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191
} Elf_SectionHeaderType;

struct Elf64_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType sh_type;
    qword sh_flags;
    qword sh_addr;
    qword sh_offset;
    qword sh_size;
    dword sh_link;
    dword sh_info;
    qword sh_addralign;
    qword sh_entsize;
};

typedef struct Elf64_Sym Elf64_Sym, *PElf64_Sym;

struct Elf64_Sym {
    dword st_name;
    byte st_info;
    byte st_other;
    word st_shndx;
    qword st_value;
    qword st_size;
};

typedef struct GnuBuildId GnuBuildId, *PGnuBuildId;

struct GnuBuildId {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    byte hash[20];
};

typedef struct NoteGnuProperty_4 NoteGnuProperty_4, *PNoteGnuProperty_4;

struct NoteGnuProperty_4 {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
};

typedef struct Elf64_Ehdr Elf64_Ehdr, *PElf64_Ehdr;

struct Elf64_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    qword e_entry;
    qword e_phoff;
    qword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

typedef struct Elf64_Phdr Elf64_Phdr, *PElf64_Phdr;

struct Elf64_Phdr {
    enum Elf_ProgramHeaderType p_type;
    dword p_flags;
    qword p_offset;
    qword p_vaddr;
    qword p_paddr;
    qword p_filesz;
    qword p_memsz;
    qword p_align;
};

typedef struct NoteAbiTag NoteAbiTag, *PNoteAbiTag;

struct NoteAbiTag {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    dword abiType; // 0 == Linux
    dword requiredKernelVersion[3]; // Major.minor.patch
};

typedef ushort uint16_t;




void _DT_INIT(void)

{
  if (true) {
    __gmon_start__();
  }
  return;
}



void FUN_00102020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



void FUN_00102510(void)

{
  __cxa_finalize();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * inet_ntop(int __af,void *__cp,char *__buf,socklen_t __len)

{
  char *pcVar1;
  
  pcVar1 = inet_ntop(__af,__cp,__buf,__len);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t recv(int __fd,void *__buf,size_t __n,int __flags)

{
  ssize_t sVar1;
  
  sVar1 = recv(__fd,__buf,__n,__flags);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strcasecmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcasecmp(__s1,__s2);
  return iVar1;
}



void g_string_new(void)

{
  g_string_new();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int * __errno_location(void)

{
  int *piVar1;
  
  piVar1 = __errno_location();
  return piVar1;
}



void g_malloc(void)

{
  g_malloc();
  return;
}



void g_free(void)

{
  g_free();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcpy(char *__dest,char *__src)

{
  char *pcVar1;
  
  pcVar1 = strcpy(__dest,__src);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void qsort(void *__base,size_t __nmemb,size_t __size,__compar_fn_t __compar)

{
  qsort(__base,__nmemb,__size,__compar);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int setsockopt(int __fd,int __level,int __optname,void *__optval,socklen_t __optlen)

{
  int iVar1;
  
  iVar1 = setsockopt(__fd,__level,__optname,__optval,__optlen);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fcntl(int __fd,int __cmd,...)

{
  int iVar1;
  
  iVar1 = fcntl(__fd,__cmd);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * inet_ntoa(in_addr __in)

{
  char *pcVar1;
  
  pcVar1 = inet_ntoa(__in);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int getpeername(int __fd,sockaddr *__addr,socklen_t *__len)

{
  int iVar1;
  
  iVar1 = getpeername(__fd,__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fclose(__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int shutdown(int __fd,int __how)

{
  int iVar1;
  
  iVar1 = shutdown(__fd,__how);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint16_t htons(uint16_t __hostshort)

{
  uint16_t uVar1;
  
  uVar1 = htons(__hostshort);
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t send(int __fd,void *__buf,size_t __n,int __flags)

{
  ssize_t sVar1;
  
  sVar1 = send(__fd,__buf,__n,__flags);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strchr(char *__s,int __c)

{
  char *pcVar1;
  
  pcVar1 = strchr(__s,__c);
  return pcVar1;
}



void g_rand_free(void)

{
  g_rand_free();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__off_t lseek(int __fd,__off_t __offset,int __whence)

{
  __off_t _Var1;
  
  _Var1 = lseek(__fd,__offset,__whence);
  return _Var1;
}



void g_assertion_message_expr(void)

{
  g_assertion_message_expr();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void __assert_fail(char *__assertion,char *__file,uint __line,char *__function)

{
                    // WARNING: Subroutine does not return
  __assert_fail(__assertion,__file,__line,__function);
}



void g_return_if_fail_warning(void)

{
  g_return_if_fail_warning();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint32_t htonl(uint32_t __hostlong)

{
  uint32_t uVar1;
  
  uVar1 = htonl(__hostlong);
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



void g_strerror(void)

{
  g_strerror();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int ioctl(int __fd,ulong __request,...)

{
  int iVar1;
  
  iVar1 = ioctl(__fd,__request);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t sendto(int __fd,void *__buf,size_t __n,int __flags,sockaddr *__addr,socklen_t __addr_len)

{
  ssize_t sVar1;
  
  sVar1 = sendto(__fd,__buf,__n,__flags,__addr,__addr_len);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

{
  int iVar1;
  
  iVar1 = close(__fd);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__pid_t setsid(void)

{
  __pid_t _Var1;
  
  _Var1 = setsid();
  return _Var1;
}



void g_string_free(void)

{
  g_string_free();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;
  
  sVar1 = read(__fd,__buf,__nbytes);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int memcmp(void *__s1,void *__s2,size_t __n)

{
  int iVar1;
  
  iVar1 = memcmp(__s1,__s2,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * fgets(char *__s,int __n,FILE *__stream)

{
  char *pcVar1;
  
  pcVar1 = fgets(__s,__n,__stream);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int getsockopt(int __fd,int __level,int __optname,void *__optval,socklen_t *__optlen)

{
  int iVar1;
  
  iVar1 = getsockopt(__fd,__level,__optname,__optval,__optlen);
  return iVar1;
}



void g_rand_new(void)

{
  g_rand_new();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint if_nametoindex(char *__ifname)

{
  uint uVar1;
  
  uVar1 = if_nametoindex(__ifname);
  return uVar1;
}



void g_warn_message(void)

{
  g_warn_message();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



void g_vsnprintf(void)

{
  g_vsnprintf();
  return;
}



void g_strstr_len(void)

{
  g_strstr_len();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int inet_pton(int __af,char *__cp,void *__buf)

{
  int iVar1;
  
  iVar1 = inet_pton(__af,__cp,__buf);
  return iVar1;
}



void g_strv_length(void)

{
  g_strv_length();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int __xstat(int __ver,char *__filename,stat *__stat_buf)

{
  int iVar1;
  
  iVar1 = __xstat(__ver,__filename,__stat_buf);
  return iVar1;
}



void g_malloc_n(void)

{
  g_malloc_n();
  return;
}



void __isoc99_sscanf(void)

{
  __isoc99_sscanf();
  return;
}



void g_rand_int_range(void)

{
  g_rand_int_range();
  return;
}



void g_parse_debug_string(void)

{
  g_parse_debug_string();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int listen(int __fd,int __n)

{
  int iVar1;
  
  iVar1 = listen(__fd,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t recvfrom(int __fd,void *__buf,size_t __n,int __flags,sockaddr *__addr,socklen_t *__addr_len)

{
  ssize_t sVar1;
  
  sVar1 = recvfrom(__fd,__buf,__n,__flags,__addr,__addr_len);
  return sVar1;
}



void g_shell_parse_argv(void)

{
  g_shell_parse_argv();
  return;
}



void g_strfreev(void)

{
  g_strfreev();
  return;
}



void g_string_append_printf(void)

{
  g_string_append_printf();
  return;
}



void g_log(void)

{
  g_log();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint16_t ntohs(uint16_t __netshort)

{
  uint16_t uVar1;
  
  uVar1 = ntohs(__netshort);
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int bind(int __fd,sockaddr *__addr,socklen_t __len)

{
  int iVar1;
  
  iVar1 = bind(__fd,__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memmove(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memmove(__dest,__src,__n);
  return pvVar1;
}



void g_malloc0_n(void)

{
  g_malloc0_n();
  return;
}



void g_realloc(void)

{
  g_realloc();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int open(char *__file,int __oflag,...)

{
  int iVar1;
  
  iVar1 = open(__file,__oflag);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



void g_spawn_async_with_fds(void)

{
  g_spawn_async_with_fds();
  return;
}



void g_malloc0(void)

{
  g_malloc0();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int accept(int __fd,sockaddr *__addr,socklen_t *__addr_len)

{
  int iVar1;
  
  iVar1 = accept(__fd,__addr,__addr_len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int getsockname(int __fd,sockaddr *__addr,socklen_t *__len)

{
  int iVar1;
  
  iVar1 = getsockname(__fd,__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int atoi(char *__nptr)

{
  int iVar1;
  
  iVar1 = atoi(__nptr);
  return iVar1;
}



void g_strdup(void)

{
  g_strdup();
  return;
}



void g_getenv(void)

{
  g_getenv();
  return;
}



void g_snprintf(void)

{
  g_snprintf();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int connect(int __fd,sockaddr *__addr,socklen_t __len)

{
  int iVar1;
  
  iVar1 = connect(__fd,__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint32_t ntohl(uint32_t __netlong)

{
  uint32_t uVar1;
  
  uVar1 = ntohl(__netlong);
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strerror(int __errnum)

{
  char *pcVar1;
  
  pcVar1 = strerror(__errnum);
  return pcVar1;
}



void g_strlcpy(void)

{
  g_strlcpy();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strstr(char *__haystack,char *__needle)

{
  char *pcVar1;
  
  pcVar1 = strstr(__haystack,__needle);
  return pcVar1;
}



void g_error_free(void)

{
  g_error_free();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int socket(int __domain,int __type,int __protocol)

{
  int iVar1;
  
  iVar1 = socket(__domain,__type,__protocol);
  return iVar1;
}



void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined auStack_8 [8];
  
  __libc_start_main(FUN_00102ae9,param_2,&stack0x00000008,FUN_0011c030,FUN_0011c0a0,param_1,
                    auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void FUN_00102a30(void)

{
  if ((false) && (true)) {
    _ITM_deregisterTMCloneTable();
    return;
  }
  return;
}



void FUN_00102a60(void)

{
  if ((false) && (true)) {
    _ITM_registerTMCloneTable();
    return;
  }
  return;
}



void _FINI_0(void)

{
  if (DAT_00123020 == '\0') {
    if (true) {
      FUN_00102510(PTR_LOOP_00123008);
    }
    FUN_00102a30();
    DAT_00123020 = 1;
    return;
  }
  return;
}



void _INIT_0(void)

{
  FUN_00102a60();
  return;
}



undefined8 FUN_00102ae9(void)

{
  long in_FS_OFFSET;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_98 = 0;
  local_90 = 0;
  local_88 = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  FUN_00104c4c(0,0);
  FUN_001053ed(0,&local_98,0x80,0);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}



undefined8 FUN_00102c02(void *param_1,void *param_2)

{
  int iVar1;
  undefined4 extraout_var;
  
  iVar1 = memcmp(param_1,param_2,0x10);
  return CONCAT71((int7)(CONCAT44(extraout_var,iVar1) >> 8),iVar1 == 0);
}



void FUN_00102c31(undefined8 param_1,undefined8 param_2,undefined *param_3)

{
  undefined4 uStack_1c;
  
  *param_3 = 0x52;
  param_3[1] = 0x56;
  uStack_1c = (undefined4)((ulong)param_2 >> 0x20);
  *(undefined4 *)(param_3 + 2) = uStack_1c;
  return;
}



undefined8 FUN_00102c6e(void *param_1,void *param_2,uint param_3,long *param_4,int *param_5)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  int iVar6;
  undefined8 uVar7;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if ((uint)(DAT_001231c8 - *param_5) < 1000) {
    memcpy(param_1,param_2,(ulong)param_3);
    uVar7 = 0;
  }
  else {
    lVar2 = *param_4;
    lVar3 = param_4[1];
    lVar4 = param_4[6];
    lVar5 = param_4[0xb];
    iVar6 = FUN_0011c0b0("/etc/resolv.conf",param_4);
    if (iVar6 == 0) {
      if ((((*param_4 == lVar2) && (param_4[1] == lVar3)) && (param_4[6] == lVar4)) &&
         (param_4[0xb] == lVar5)) {
        memcpy(param_1,param_2,(ulong)param_3);
        uVar7 = 0;
      }
      else {
        uVar7 = 1;
      }
    }
    else {
      uVar7 = 0xffffffff;
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar7;
}



undefined8
FUN_00102e62(int param_1,void *param_2,void *param_3,uint param_4,uint *param_5,undefined4 *param_6)

{
  long lVar1;
  void *pvVar2;
  void *pvVar3;
  FILE *pFVar4;
  int iVar5;
  ulong uVar6;
  undefined8 uVar7;
  char *pcVar8;
  undefined *puVar9;
  long in_FS_OFFSET;
  undefined auStack_3b8 [8];
  undefined4 *local_3b0;
  uint *local_3a8;
  void *local_3a0;
  void *local_398;
  uint local_390;
  int local_38c;
  int local_380;
  uint local_37c;
  char *local_378;
  void *local_370;
  FILE *local_368;
  char *local_360;
  char local_358 [48];
  char local_328 [272];
  char local_218 [520];
  long local_10;
  
  local_38c = param_1;
  local_398 = param_2;
  local_3a0 = param_3;
  local_390 = param_4;
  local_3a8 = param_5;
  local_3b0 = param_6;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_380 = 0;
  uVar6 = (((ulong)param_4 + 0x17) / 0x10) * 0x10;
  for (puVar9 = auStack_3b8; puVar9 != auStack_3b8 + -(uVar6 & 0xfffffffffffff000);
      puVar9 = puVar9 + -0x1000) {
    *(undefined8 *)(puVar9 + -8) = *(undefined8 *)(puVar9 + -8);
  }
  lVar1 = -(ulong)((uint)uVar6 & 0xfff);
  if ((uVar6 & 0xfff) != 0) {
    *(undefined8 *)(puVar9 + ((ulong)((uint)uVar6 & 0xfff) - 8) + lVar1) =
         *(undefined8 *)(puVar9 + ((ulong)((uint)uVar6 & 0xfff) - 8) + lVar1);
  }
  local_370 = (void *)((ulong)(puVar9 + lVar1 + 0xf) & 0xfffffffffffffff0);
  *(undefined8 *)(puVar9 + lVar1 + -8) = 0x102f56;
  local_368 = fopen("/etc/resolv.conf","r");
  if (local_368 == (FILE *)0x0) {
    uVar7 = 0xffffffff;
  }
  else {
    if ((DAT_001231c0 & 2) != 0) {
      *(undefined8 *)(puVar9 + lVar1 + -8) = 0x102f9f;
      g_log("Slirp",0x80,"IP address of your DNS(s):");
    }
    while( true ) {
      pFVar4 = local_368;
      *(undefined8 *)(puVar9 + lVar1 + -8) = 0x103197;
      pcVar8 = fgets(local_218,0x200,pFVar4);
      if (pcVar8 == (char *)0x0) break;
      *(undefined8 *)(puVar9 + lVar1 + -8) = 0x102fc6;
      iVar5 = __isoc99_sscanf(local_218,"nameserver%*[ \t]%256s",local_328);
      if (iVar5 == 1) {
        *(undefined8 *)(puVar9 + lVar1 + -8) = 0x102fe3;
        local_360 = strchr(local_328,0x25);
        if (local_360 == (char *)0x0) {
          local_37c = 0;
        }
        else {
          pcVar8 = local_360 + 1;
          *(undefined8 *)(puVar9 + lVar1 + -8) = 0x103007;
          local_37c = if_nametoindex(pcVar8);
          *local_360 = '\0';
        }
        pvVar2 = local_370;
        iVar5 = local_38c;
        *(undefined8 *)(puVar9 + lVar1 + -8) = 0x103041;
        iVar5 = inet_pton(iVar5,local_328,pvVar2);
        pvVar3 = local_370;
        pvVar2 = local_398;
        if (iVar5 != 0) {
          if (local_380 == 0) {
            uVar6 = (ulong)local_390;
            *(undefined8 *)(puVar9 + lVar1 + -8) = 0x103072;
            memcpy(pvVar2,pvVar3,uVar6);
            pvVar3 = local_370;
            pvVar2 = local_3a0;
            uVar6 = (ulong)local_390;
            *(undefined8 *)(puVar9 + lVar1 + -8) = 0x103091;
            memcpy(pvVar2,pvVar3,uVar6);
            if (local_3a8 != (uint *)0x0) {
              *local_3a8 = local_37c;
            }
            *local_3b0 = DAT_001231c8;
          }
          pvVar2 = local_370;
          iVar5 = local_38c;
          local_380 = local_380 + 1;
          if (3 < local_380) {
            if ((DAT_001231c0 & 2) != 0) {
              *(undefined8 *)(puVar9 + lVar1 + -8) = 0x1030f7;
              g_log("Slirp",0x80,"  (more)");
            }
            break;
          }
          if ((DAT_001231c0 & 2) != 0) {
            *(undefined8 *)(puVar9 + lVar1 + -8) = 0x103129;
            local_378 = inet_ntop(iVar5,pvVar2,local_358,0x2e);
            if (local_378 == (char *)0x0) {
              local_378 = "  (string conversion error)";
            }
            pcVar8 = local_378;
            if ((DAT_001231c0 & 2) != 0) {
              *(undefined8 *)(puVar9 + lVar1 + -8) = 0x10317c;
              g_log("Slirp",0x80,&DAT_0011d07d,pcVar8);
            }
          }
        }
      }
    }
    pFVar4 = local_368;
    *(undefined8 *)(puVar9 + lVar1 + -8) = 0x1031b2;
    fclose(pFVar4);
    if (local_380 == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      uVar7 = 0;
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar7;
  }
                    // WARNING: Subroutine does not return
  *(undefined8 *)(puVar9 + lVar1 + -8) = 0x1031db;
  __stack_chk_fail();
}



ulong FUN_001031dd(undefined8 param_1)

{
  uint uVar1;
  ulong uVar2;
  
  if ((DAT_00123040 != 0) &&
     (uVar1 = FUN_00102c6e(param_1,&DAT_00123040,4,&DAT_00123080,&DAT_00123060), (int)uVar1 < 1)) {
    return (ulong)uVar1;
  }
  uVar2 = FUN_00102e62(2,param_1,&DAT_00123040,4,0,&DAT_00123060);
  return uVar2;
}



ulong FUN_00103257(undefined8 param_1,undefined8 param_2)

{
  char cVar1;
  uint uVar2;
  ulong uVar3;
  long in_FS_OFFSET;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0;
  local_20 = 0;
  cVar1 = FUN_00102c02(&DAT_00123050,&local_28);
  if (cVar1 != '\x01') {
    uVar2 = FUN_00102c6e(param_1,&DAT_00123050,0x10,&DAT_00123120,&DAT_00123064);
    if ((int)uVar2 < 1) {
      uVar3 = (ulong)uVar2;
      goto LAB_00103303;
    }
  }
  uVar3 = FUN_00102e62(10,param_1,&DAT_00123050,0x10,param_2,&DAT_00123064);
LAB_00103303:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar3;
}



void FUN_00103319(void)

{
  uint32_t uVar1;
  long lVar2;
  long in_FS_OFFSET;
  undefined *local_58;
  undefined4 local_50;
  undefined *local_48;
  undefined4 local_40;
  char *local_38;
  undefined4 local_30;
  undefined *local_28;
  undefined4 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (DAT_001231b0 == 0) {
    DAT_001231b0 = 1;
    DAT_001231c4 = htonl(0x7f000001);
    uVar1 = htonl(0xff000000);
    DAT_001231b8 = (ulong)uVar1;
    lVar2 = g_getenv("SLIRP_DEBUG");
    if (lVar2 != 0) {
      local_58 = &DAT_0011d08e;
      local_50 = 1;
      local_48 = &DAT_0011d093;
      local_40 = 2;
      local_38 = "error";
      local_30 = 4;
      local_28 = &DAT_0011d09e;
      local_20 = 8;
      DAT_001231c0 = g_parse_debug_string(lVar2,&local_58,4);
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



long FUN_00103405(uint *param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  size_t sVar2;
  undefined8 uVar3;
  undefined4 uVar4;
  
  if (param_1 == (uint *)0x0) {
    g_return_if_fail_warning("Slirp","slirp_new","cfg != NULL");
    lVar1 = 0;
  }
  else if (*param_1 == 0) {
    g_return_if_fail_warning("Slirp","slirp_new","cfg->version >= SLIRP_CONFIG_VERSION_MIN");
    lVar1 = 0;
  }
  else if (*param_1 < 4) {
    if ((*(ulong *)(param_1 + 0x22) < 0x44) && (*(long *)(param_1 + 0x22) != 0)) {
      g_return_if_fail_warning("Slirp","slirp_new","cfg->if_mtu >= IF_MTU_MIN || cfg->if_mtu == 0");
      lVar1 = 0;
    }
    else if (*(ulong *)(param_1 + 0x22) < 0xfff2) {
      if ((*(ulong *)(param_1 + 0x24) < 0x44) && (*(long *)(param_1 + 0x24) != 0)) {
        g_return_if_fail_warning
                  ("Slirp","slirp_new","cfg->if_mru >= IF_MRU_MIN || cfg->if_mru == 0");
        lVar1 = 0;
      }
      else if (*(ulong *)(param_1 + 0x24) < 0xfff2) {
        if ((*(long *)(param_1 + 0x16) == 0) ||
           (sVar2 = strlen(*(char **)(param_1 + 0x16)), sVar2 < 0x80)) {
          lVar1 = g_malloc0(0x1790);
          FUN_00103319();
          *(undefined8 *)(lVar1 + 6000) = param_3;
          *(undefined8 *)(lVar1 + 0x1768) = param_2;
          uVar3 = g_rand_new();
          *(undefined8 *)(lVar1 + 0x1750) = uVar3;
          *(uint *)(lVar1 + 0x7c) = param_1[1];
          *(undefined *)(lVar1 + 9) = *(undefined *)(param_1 + 2);
          *(undefined *)(lVar1 + 10) = *(undefined *)(param_1 + 6);
          FUN_0010d0f7(lVar1);
          FUN_001162ac(lVar1);
          FUN_0011945e(lVar1);
          FUN_00110b93(lVar1);
          *(uint *)(lVar1 + 0xc) = param_1[3];
          *(uint *)(lVar1 + 0x10) = param_1[4];
          *(uint *)(lVar1 + 0x14) = param_1[5];
          uVar3 = *(undefined8 *)(param_1 + 9);
          *(undefined8 *)(lVar1 + 0x18) = *(undefined8 *)(param_1 + 7);
          *(undefined8 *)(lVar1 + 0x20) = uVar3;
          *(undefined *)(lVar1 + 0x28) = *(undefined *)(param_1 + 0xb);
          uVar3 = *(undefined8 *)(param_1 + 0xe);
          *(undefined8 *)(lVar1 + 0x2c) = *(undefined8 *)(param_1 + 0xc);
          *(undefined8 *)(lVar1 + 0x34) = uVar3;
          if (*(long *)(param_1 + 0x10) != 0) {
            FUN_0010823b(lVar1 + 0x58,0x21,*(undefined8 *)(param_1 + 0x10));
          }
          uVar3 = g_strdup(*(undefined8 *)(param_1 + 0x14));
          *(undefined8 *)(lVar1 + 0x6d8) = uVar3;
          uVar3 = g_strdup(*(undefined8 *)(param_1 + 0x16));
          *(undefined8 *)(lVar1 + 0x1a0) = uVar3;
          uVar3 = g_strdup(*(undefined8 *)(param_1 + 0x20));
          *(undefined8 *)(lVar1 + 0x1b8) = uVar3;
          *(uint *)(lVar1 + 0x3c) = param_1[0x18];
          *(uint *)(lVar1 + 0x40) = param_1[0x19];
          uVar3 = *(undefined8 *)(param_1 + 0x1c);
          *(undefined8 *)(lVar1 + 0x44) = *(undefined8 *)(param_1 + 0x1a);
          *(undefined8 *)(lVar1 + 0x4c) = uVar3;
          uVar3 = g_strdup(*(undefined8 *)(param_1 + 0x12));
          *(undefined8 *)(lVar1 + 0x1400) = uVar3;
          if (*(long *)(param_1 + 0x1e) != 0) {
            FUN_001092c3(lVar1,*(undefined8 *)(param_1 + 0x1e));
          }
          if (*(long *)(param_1 + 0x22) == 0) {
            uVar4 = 0x5dc;
          }
          else {
            uVar4 = (undefined4)*(undefined8 *)(param_1 + 0x22);
          }
          *(undefined4 *)(lVar1 + 0x88) = uVar4;
          if (*(long *)(param_1 + 0x24) == 0) {
            uVar4 = 0x5dc;
          }
          else {
            uVar4 = (undefined4)*(undefined8 *)(param_1 + 0x24);
          }
          *(undefined4 *)(lVar1 + 0x8c) = uVar4;
          *(undefined *)(lVar1 + 0x90) = *(undefined *)(param_1 + 0x26);
          *(undefined *)(lVar1 + 0x1760) = *(undefined *)((long)param_1 + 0x99);
          if (*param_1 < 2) {
            *(undefined8 *)(lVar1 + 0x1778) = 0;
            *(undefined8 *)(lVar1 + 0x1780) = 0;
          }
          else {
            *(undefined8 *)(lVar1 + 0x1778) = *(undefined8 *)(param_1 + 0x28);
            *(undefined8 *)(lVar1 + 0x1780) = *(undefined8 *)(param_1 + 0x2a);
          }
          if (*param_1 < 3) {
            *(undefined *)(lVar1 + 0x1788) = 0;
          }
          else {
            *(undefined *)(lVar1 + 0x1788) = *(undefined *)(param_1 + 0x2c);
          }
        }
        else {
          g_return_if_fail_warning
                    ("Slirp","slirp_new",
                     "!cfg->bootfile || (strlen(cfg->bootfile) < G_SIZEOF_MEMBER(struct bootp_t, bp_file))"
                    );
          lVar1 = 0;
        }
      }
      else {
        g_return_if_fail_warning("Slirp","slirp_new","cfg->if_mru <= IF_MRU_MAX");
        lVar1 = 0;
      }
    }
    else {
      g_return_if_fail_warning("Slirp","slirp_new","cfg->if_mtu <= IF_MTU_MAX");
      lVar1 = 0;
    }
  }
  else {
    g_return_if_fail_warning("Slirp","slirp_new","cfg->version <= SLIRP_CONFIG_VERSION_MAX");
    lVar1 = 0;
  }
  return lVar1;
}



void FUN_001038fa(undefined4 param_1,undefined param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined param_6,undefined8 param_7,undefined8 param_8,
                 undefined param_9,undefined8 param_10,undefined8 param_11,undefined8 param_12,
                 undefined8 param_13,undefined8 param_14,undefined8 param_15,undefined4 param_16,
                 undefined4 param_17,undefined8 param_18,undefined8 param_19,undefined8 param_20,
                 undefined8 param_21,undefined8 param_22,undefined8 param_23)

{
  long in_FS_OFFSET;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined local_b0;
  undefined8 local_ac;
  undefined8 local_a4;
  undefined local_9c;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined4 local_68;
  undefined4 local_64;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  memset(&local_c8,0,0xb8);
  local_c8 = 1;
  local_ac = param_7;
  local_a4 = param_8;
  local_98 = param_10;
  local_90 = param_11;
  local_88 = param_12;
  local_80 = param_13;
  local_78 = param_14;
  local_70 = param_15;
  local_68 = param_16;
  local_64 = param_17;
  local_60 = param_18;
  local_58 = param_19;
  local_50 = param_20;
  local_48 = param_21;
  local_c4 = param_1;
  local_c0 = param_2;
  local_bc = param_3;
  local_b8 = param_4;
  local_b4 = param_5;
  local_b0 = param_6;
  local_9c = param_9;
  FUN_00103405(&local_c8,param_22,param_23);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_00103aea(long param_1)

{
  long lVar1;
  undefined8 local_18;
  
  local_18 = *(long *)(param_1 + 0x80);
  while (local_18 != 0) {
    lVar1 = *(long *)(local_18 + 0x28);
    g_free(*(undefined8 *)(local_18 + 0x18));
    g_free(*(undefined8 *)(local_18 + 0x20));
    g_free(local_18);
    local_18 = lVar1;
  }
  FUN_0011630f(param_1);
  FUN_0011947d(param_1);
  FUN_00110bfa(param_1);
  g_rand_free(*(undefined8 *)(param_1 + 0x1750));
  g_free(*(undefined8 *)(param_1 + 0x1b0));
  g_free(*(undefined8 *)(param_1 + 0x6d8));
  g_free(*(undefined8 *)(param_1 + 0x1a0));
  g_free(*(undefined8 *)(param_1 + 0x1b8));
  g_free(param_1);
  return;
}



void FUN_00103be4(int *param_1,uint *param_2)

{
  uint uVar1;
  uint local_c;
  
  if (2 < *param_2) {
    uVar1 = *param_2;
    if (1000 < uVar1) {
      uVar1 = 1000;
    }
    if (*param_1 == 0) {
      local_c = uVar1;
      if ((*(char *)(param_1 + 2) != '\0') && (local_c = 499, uVar1 < 500)) {
        local_c = uVar1;
      }
      *param_2 = local_c;
    }
    else {
      *param_2 = 2;
    }
  }
  return;
}



void FUN_00103c58(uint *param_1,undefined8 param_2,code *param_3,undefined8 param_4)

{
  uint *puVar1;
  undefined uVar2;
  uint uVar3;
  uint local_1c;
  uint *local_18;
  
  if ((*(uint **)(param_1 + 0x70) == param_1 + 0x70) &&
     (param_1 + 0x3e == *(uint **)(param_1 + 0x3e))) {
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  *(undefined *)(param_1 + 2) = uVar2;
  puVar1 = *(uint **)(param_1 + 0x70);
  while (local_18 = puVar1, local_18 != param_1 + 0x70) {
    local_1c = 0;
    puVar1 = *(uint **)local_18;
    local_18[8] = 0xffffffff;
    if ((*param_1 == 0) && ((*(ushort *)(*(long *)(local_18 + 0x54) + 0x24) & 2) != 0)) {
      *param_1 = DAT_001231c8;
    }
    if (((local_18[0x53] & 1) == 0) && (local_18[4] != 0xffffffff)) {
      if ((local_18[0x53] & 0x100) == 0) {
        if ((local_18[0x53] & 2) == 0) {
          if (((local_18[0x53] & 0x14) == 4) && (local_18[0x5a] != 0)) {
            local_1c = 10;
          }
          if (((local_18[0x53] & 0xc) == 4) && (local_18[0x62] < local_18[99] >> 1)) {
            local_1c = local_1c | 0x1d;
          }
          if (local_1c != 0) {
            uVar3 = (*param_3)(local_18[4],local_1c,param_4);
            local_18[8] = uVar3;
          }
        }
        else {
          uVar3 = (*param_3)(local_18[4],10,param_4);
          local_18[8] = uVar3;
        }
      }
      else {
        uVar3 = (*param_3)(local_18[4],0x19,param_4);
        local_18[8] = uVar3;
      }
    }
  }
  puVar1 = *(uint **)(param_1 + 0xde);
LAB_00103ef0:
  local_18 = puVar1;
  if (local_18 != param_1 + 0xde) {
    puVar1 = *(uint **)local_18;
    local_18[8] = 0xffffffff;
    if (local_18[0x56] != 0) {
      if (local_18[0x56] <= DAT_001231c8) {
        FUN_0010a15c(local_18);
        goto LAB_00103ef0;
      }
      *(undefined *)(param_1 + 2) = 1;
    }
    if (((local_18[0x53] & 4) != 0) && ((int)local_18[0x57] < 5)) {
      uVar3 = (*param_3)(local_18[4],0x19,param_4);
      local_18[8] = uVar3;
    }
    goto LAB_00103ef0;
  }
  puVar1 = *(uint **)(param_1 + 0x14a);
LAB_00103f9e:
  do {
    local_18 = puVar1;
    if (local_18 == param_1 + 0x14a) {
      FUN_00103be4(param_1,param_2);
      return;
    }
    puVar1 = *(uint **)local_18;
    local_18[8] = 0xffffffff;
    if (local_18[0x56] != 0) {
      if (local_18[0x56] <= DAT_001231c8) {
        FUN_0011787b(local_18);
        goto LAB_00103f9e;
      }
      *(undefined *)(param_1 + 2) = 1;
    }
    if ((local_18[0x53] & 4) != 0) {
      uVar3 = (*param_3)(local_18[4],0x19,param_4);
      local_18[8] = uVar3;
    }
  } while( true );
}



void FUN_00103fc8(int *param_1,int param_2,code *param_3,undefined8 param_4)

{
  long lVar1;
  ssize_t sVar2;
  int *piVar3;
  long in_FS_OFFSET;
  int local_30;
  uint local_2c;
  uint local_28;
  uint local_24;
  int *local_20;
  int *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = (**(code **)(*(long *)(param_1 + 0x5da) + 0x10))(*(undefined8 *)(param_1 + 0x5dc));
  DAT_001231c8 = (int)(lVar1 / 1000000);
  if ((*param_1 != 0) && (1 < (uint)(DAT_001231c8 - *param_1))) {
    FUN_00112ec9(param_1);
    *param_1 = 0;
  }
  if ((*(char *)(param_1 + 2) != '\0') && (0x1f2 < (uint)(DAT_001231c8 - param_1[1]))) {
    FUN_00116d71(param_1);
    FUN_00112f6e(param_1);
    param_1[1] = DAT_001231c8;
  }
  if (param_2 == 0) {
    local_20 = *(int **)(param_1 + 0x70);
    while (local_20 != param_1 + 0x70) {
      local_18 = *(int **)local_20;
      local_2c = 0;
      if (local_20[8] != -1) {
        local_2c = (*param_3)(local_20[8],param_4);
      }
      if (((local_20[0x53] & 1U) == 0) && (local_20[4] != -1)) {
        if ((local_2c & 4) == 0) {
          if ((local_2c & 0x19) != 0) {
            if ((local_20[0x53] & 0x100U) != 0) {
              FUN_0010ece8(local_20);
              goto LAB_001042fc;
            }
            local_30 = FUN_00113d10(local_20);
            if (0 < local_30) {
              FUN_00105b44(*(undefined8 *)(local_20 + 0x54));
            }
            goto joined_r0x001041b4;
          }
        }
        else {
          local_30 = FUN_0011432e(local_20);
joined_r0x001041b4:
          if (local_30 < 0) goto LAB_001042fc;
        }
        if (((local_20[0x53] & 1U) == 0) && ((local_2c & 10) != 0)) {
          if ((local_20[0x53] & 2U) == 0) {
            local_30 = FUN_00114789(local_20);
            if (0 < local_30) {
              FUN_00105b44(*(undefined8 *)(local_20 + 0x54));
            }
          }
          else {
            local_20[0x53] = local_20[0x53] & 0xfffffffd;
            sVar2 = send(local_20[4],&local_30,0,0);
            local_30 = (int)sVar2;
            if (local_30 < 0) {
              piVar3 = __errno_location();
              if ((((*piVar3 == 0xb) || (piVar3 = __errno_location(), *piVar3 == 0xb)) ||
                  (piVar3 = __errno_location(), *piVar3 == 0x73)) ||
                 (piVar3 = __errno_location(), *piVar3 == 0x6b)) goto LAB_001042fc;
              local_20[0x53] = local_20[0x53] & 0xf000;
              local_20[0x53] = local_20[0x53] | 1;
            }
            FUN_0010a803(0,0x14,local_20,*(undefined2 *)(local_20 + 0x12));
          }
        }
      }
LAB_001042fc:
      local_20 = local_18;
    }
    local_20 = *(int **)(param_1 + 0xde);
    while (local_20 != param_1 + 0xde) {
      local_18 = *(int **)local_20;
      local_28 = 0;
      if (local_20[8] != -1) {
        local_28 = (*param_3)(local_20[8],param_4);
      }
      if ((local_20[4] != -1) && ((local_28 & 0x19) != 0)) {
        FUN_00114b2f(local_20);
      }
      local_20 = local_18;
    }
    local_20 = *(int **)(param_1 + 0x14a);
    while (local_20 != param_1 + 0x14a) {
      local_18 = *(int **)local_20;
      local_24 = 0;
      if (local_20[8] != -1) {
        local_24 = (*param_3)(local_20[8],param_4);
      }
      if ((local_20[4] != -1) && ((local_24 & 0x19) != 0)) {
        FUN_0011844e(local_20);
      }
      local_20 = local_18;
    }
  }
  FUN_0010d3f3(param_1);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0010443f(long param_1,long param_2)

{
  uint16_t uVar1;
  long in_FS_OFFSET;
  long local_78;
  undefined local_58 [6];
  undefined local_52 [2];
  undefined4 local_50;
  uint16_t local_4c;
  uint16_t local_4a;
  uint16_t local_48;
  undefined local_46;
  undefined local_45;
  uint16_t local_44;
  undefined auStack_42 [6];
  undefined4 local_3c;
  undefined auStack_38 [6];
  undefined4 local_32;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (*(char *)(param_1 + 9) == '\x01') {
    uVar1 = ntohs(*(uint16_t *)(param_2 + 0x14));
    if (uVar1 == 1) {
      if (*(int *)(param_2 + 0x26) == *(int *)(param_2 + 0x1c)) {
        FUN_00107c71(param_1,*(undefined4 *)(param_2 + 0x1c),param_2 + 0x16);
      }
      else if ((*(uint *)(param_2 + 0x26) & *(uint *)(param_1 + 0x10)) == *(uint *)(param_1 + 0xc))
      {
        if ((*(int *)(param_2 + 0x26) == *(int *)(param_1 + 0x40)) ||
           (*(int *)(param_2 + 0x26) == *(int *)(param_1 + 0x14))) {
LAB_0010459f:
          memset(local_58,0,0x40);
          FUN_00107c71(param_1,*(undefined4 *)(param_2 + 0x1c),param_2 + 0x16);
          memcpy(local_58,(void *)(param_2 + 6),6);
          memcpy(local_52,&DAT_0011d008,2);
          local_50 = *(undefined4 *)(param_2 + 0x26);
          local_4c = htons(0x806);
          local_4a = htons(1);
          local_48 = htons(0x800);
          local_46 = 6;
          local_45 = 4;
          local_44 = htons(2);
          memcpy(auStack_42,local_52,6);
          local_3c = *(undefined4 *)(param_2 + 0x26);
          memcpy(auStack_38,(void *)(param_2 + 0x16),6);
          local_32 = *(undefined4 *)(param_2 + 0x1c);
          FUN_00105632(param_1,local_58,0x40);
        }
        else {
          for (local_78 = *(long *)(param_1 + 0x80); local_78 != 0;
              local_78 = *(long *)(local_78 + 0x28)) {
            if (*(int *)(local_78 + 0x10) == *(int *)(param_2 + 0x26)) goto LAB_0010459f;
          }
        }
      }
    }
    else if (uVar1 == 2) {
      FUN_00107c71(param_1,*(undefined4 *)(param_2 + 0x1c),param_2 + 0x16);
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00104730(undefined8 param_1,void *param_2,int param_3)

{
  uint uVar1;
  long lVar2;
  long lVar3;
  
  if (0xd < param_3) {
    uVar1 = (uint)*(byte *)((long)param_2 + 0xd) + (uint)*(byte *)((long)param_2 + 0xc) * 0x100;
    if (uVar1 == 0x88f8) {
      FUN_0010583e(param_1,param_2,param_3);
    }
    else if (uVar1 < 0x88f9) {
      if (uVar1 != 0x86dd) {
        if (0x86dd < uVar1) {
          return;
        }
        if (uVar1 != 0x800) {
          if (uVar1 != 0x806) {
            return;
          }
          FUN_0010443f(param_1,param_2,param_3);
          return;
        }
      }
      lVar2 = FUN_00110cac(param_1);
      if (lVar2 != 0) {
        if ((*(uint *)(lVar2 + 0x20) & 1) == 0) {
          lVar3 = (lVar2 + 0x60 + (long)*(int *)(lVar2 + 0x24)) - *(long *)(lVar2 + 0x30);
        }
        else {
          lVar3 = (*(long *)(lVar2 + 0x58) + (long)*(int *)(lVar2 + 0x24)) - *(long *)(lVar2 + 0x30)
          ;
        }
        if (lVar3 - *(int *)(lVar2 + 0x38) < (long)(param_3 + 0x1e)) {
          FUN_00111017(lVar2,param_3 + 0x1e);
        }
        *(int *)(lVar2 + 0x38) = param_3 + 0x1e;
        memcpy((void *)(*(long *)(lVar2 + 0x30) + 0x1e),param_2,(long)param_3);
        *(long *)(lVar2 + 0x30) = *(long *)(lVar2 + 0x30) + 0x2c;
        *(int *)(lVar2 + 0x38) = *(int *)(lVar2 + 0x38) + -0x2c;
        if (uVar1 == 0x800) {
          FUN_00116346(lVar2);
        }
        else if (uVar1 == 0x86dd) {
          FUN_0011949c(lVar2);
        }
      }
    }
  }
  return;
}



undefined8 FUN_0010491d(long param_1,long param_2,long param_3,undefined8 param_4)

{
  char cVar1;
  uint16_t uVar2;
  long lVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  undefined local_48 [6];
  undefined auStack_42 [2];
  undefined4 local_40;
  uint16_t local_3c;
  uint16_t local_3a;
  uint16_t local_38;
  undefined local_36;
  undefined local_35;
  uint16_t local_34;
  undefined auStack_32 [2];
  undefined4 local_30;
  undefined4 local_2c;
  undefined auStack_28 [6];
  undefined4 local_22;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar3 = *(long *)(param_2 + 0x30);
  cVar1 = FUN_00107ec0(param_1,*(undefined4 *)(lVar3 + 0x10),param_4);
  if (cVar1 == '\x01') {
    memcpy((void *)(param_3 + 6),&DAT_0011d008,2);
    *(undefined4 *)(param_3 + 8) = *(undefined4 *)(param_1 + 0x14);
    uVar2 = htons(0x800);
    *(uint16_t *)(param_3 + 0xc) = uVar2;
    uVar4 = 2;
  }
  else {
    if (*(char *)(param_2 + 0x48) != '\x01') {
      memset(local_48,0xff,6);
      memcpy(auStack_42,&DAT_0011d008,2);
      local_40 = *(undefined4 *)(param_1 + 0x14);
      local_3c = htons(0x806);
      local_3a = htons(1);
      local_38 = htons(0x800);
      local_36 = 6;
      local_35 = 4;
      local_34 = htons(1);
      memcpy(auStack_32,&DAT_0011d008,2);
      local_30 = *(undefined4 *)(param_1 + 0x14);
      local_2c = *(undefined4 *)(param_1 + 0x14);
      memset(auStack_28,0,6);
      local_22 = *(undefined4 *)(lVar3 + 0x10);
      *(undefined4 *)(param_1 + 0x54) = *(undefined4 *)(lVar3 + 0x10);
      FUN_00105632(param_1,local_48,0x2a);
      *(undefined *)(param_2 + 0x48) = 1;
      lVar3 = (**(code **)(*(long *)(param_1 + 0x1768) + 0x10))(*(undefined8 *)(param_1 + 6000));
      *(long *)(param_2 + 0x50) = lVar3 + 1000000000;
    }
    uVar4 = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar4;
}



undefined8 FUN_00104b62(long param_1,long param_2,long param_3,undefined8 param_4)

{
  char cVar1;
  uint16_t uVar2;
  long lVar3;
  undefined8 uVar4;
  
  lVar3 = *(long *)(param_2 + 0x30);
  cVar1 = FUN_0011720e(param_1,*(undefined8 *)(lVar3 + 0x18),*(undefined8 *)(lVar3 + 0x20),param_4);
  if (cVar1 == '\x01') {
    uVar2 = htons(0x86dd);
    *(uint16_t *)(param_3 + 0xc) = uVar2;
    FUN_00102c31(*(undefined8 *)(lVar3 + 8),*(undefined8 *)(lVar3 + 0x10),param_3 + 6);
    uVar4 = 2;
  }
  else {
    if (*(char *)(param_2 + 0x48) != '\x01') {
      FUN_00112055(param_1,*(undefined8 *)(lVar3 + 0x18),*(undefined8 *)(lVar3 + 0x20));
      *(undefined *)(param_2 + 0x48) = 1;
      lVar3 = (**(code **)(*(long *)(param_1 + 0x1768) + 0x10))(*(undefined8 *)(param_1 + 6000));
      *(long *)(param_2 + 0x50) = lVar3 + 1000000000;
    }
    uVar4 = 0;
  }
  return uVar4;
}



int FUN_00104c4c(undefined8 param_1,long param_2)

{
  void *__src;
  undefined *puVar1;
  byte bVar2;
  int iVar3;
  undefined *puVar4;
  long in_FS_OFFSET;
  undefined4 uStack_1006e;
  undefined2 uStack_1006a;
  undefined4 uStack_10068;
  undefined2 uStack_10064;
  undefined uStack_10062;
  undefined uStack_10061;
  undefined uStack_10060;
  byte bStack_1005f;
  byte bStack_1005e;
  byte bStack_1005d;
  undefined auStack_1005a [82];
  undefined auStack_10008 [65528];
  long local_10;
  
  puVar1 = &stack0xfffffffffffffff8;
  do {
    puVar4 = puVar1;
    *(undefined8 *)(puVar4 + -0x1000) = *(undefined8 *)(puVar4 + -0x1000);
    puVar1 = puVar4 + -0x1000;
  } while (puVar4 + -0x1000 != auStack_10008);
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (0x10055 < *(int *)(param_2 + 0x38) + 0xeU) {
    iVar3 = 1;
    goto LAB_00104f31;
  }
  bVar2 = **(byte **)(param_2 + 0x30) >> 4;
  if (bVar2 == 4) {
    *(undefined8 *)(puVar4 + -0x1098) = 0x104d0f;
    iVar3 = FUN_0010491d(param_1,param_2,&uStack_10068,&uStack_1006e);
joined_r0x00104d1c:
    if (iVar3 < 2) goto LAB_00104f31;
  }
  else {
    if (bVar2 == 6) {
      *(undefined8 *)(puVar4 + -0x1098) = 0x104d4d;
      iVar3 = FUN_00104b62(param_1,param_2,&uStack_10068,&uStack_1006e);
      goto joined_r0x00104d1c;
    }
    *(undefined8 *)(puVar4 + -0x1098) = 0x104d8c;
    g_assertion_message_expr
              ("Slirp",
               "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/slirp.c"
               ,0x3d1,"if_encap",0);
  }
  uStack_10068 = uStack_1006e;
  uStack_10064 = uStack_1006a;
  if ((DAT_001231c0 & 1) != 0) {
    *(ulong *)(puVar4 + -0x10a0) = (ulong)bStack_1005d;
    *(ulong *)(puVar4 + -0x10a8) = (ulong)bStack_1005e;
    *(ulong *)(puVar4 + -0x10b0) = (ulong)bStack_1005f;
    *(undefined8 *)(puVar4 + -0x10b8) = 0x104e3c;
    g_log("Slirp",0x80," src = %02x:%02x:%02x:%02x:%02x:%02x",uStack_10062,uStack_10061,uStack_10060
         );
  }
  if ((DAT_001231c0 & 1) != 0) {
    *(ulong *)(puVar4 + -0x10a0) = (ulong)uStack_10064._1_1_;
    *(ulong *)(puVar4 + -0x10a8) = (ulong)(byte)uStack_10064;
    *(ulong *)(puVar4 + -0x10b0) = (ulong)uStack_10068._3_1_;
    *(undefined8 *)(puVar4 + -0x10b8) = 0x104ed1;
    g_log("Slirp",0x80," dst = %02x:%02x:%02x:%02x:%02x:%02x",(undefined)uStack_10068,
          uStack_10068._1_1_,uStack_10068._2_1_);
  }
  iVar3 = *(int *)(param_2 + 0x38);
  __src = *(void **)(param_2 + 0x30);
  *(undefined8 *)(puVar4 + -0x1098) = 0x104f03;
  memcpy(auStack_1005a,__src,(long)iVar3);
  iVar3 = *(int *)(param_2 + 0x38);
  *(undefined8 *)(puVar4 + -0x1098) = 0x104f2c;
  FUN_00105632(param_1,&uStack_10068,(long)(iVar3 + 0xe));
  iVar3 = 1;
LAB_00104f31:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    *(undefined8 *)(puVar4 + -0x1098) = 0x104f45;
    __stack_chk_fail();
  }
  return iVar3;
}



undefined8 FUN_00104f47(long param_1,int param_2,int param_3,uint16_t param_4)

{
  uint16_t uVar1;
  int iVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  socklen_t local_40;
  uint local_3c;
  undefined8 *local_38;
  undefined8 *local_30;
  sockaddr local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_2 == 0) {
    local_30 = (undefined8 *)(param_1 + 0x1c0);
  }
  else {
    local_30 = (undefined8 *)(param_1 + 0x378);
  }
  uVar1 = htons(param_4);
  local_3c = (uint)uVar1;
  local_38 = (undefined8 *)*local_30;
  do {
    if (local_38 == local_30) {
      uVar3 = 0xffffffff;
LAB_00105072:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
        __stack_chk_fail();
      }
      return uVar3;
    }
    local_40 = 0x10;
    if ((*(uint *)((long)local_38 + 0x14c) & 0x1000) != 0) {
      iVar2 = getsockname(*(int *)(local_38 + 2),&local_28,&local_40);
      if (((iVar2 == 0) && (local_28.sa_data._2_4_ == param_3)) &&
         (local_3c == (ushort)local_28.sa_data._0_2_)) {
        (**(code **)(*(long *)(local_38[5] + 0x1768) + 0x38))
                  (*(undefined4 *)(local_38 + 2),*(undefined8 *)(local_38[5] + 6000));
        close(*(int *)(local_38 + 2));
        FUN_0011385c(local_38);
        uVar3 = 0;
        goto LAB_00105072;
      }
    }
    local_38 = (undefined8 *)*local_38;
  } while( true );
}



undefined8
FUN_00105088(long param_1,int param_2,undefined4 param_3,uint16_t param_4,int param_5,
            uint16_t param_6)

{
  uint16_t uVar1;
  uint16_t uVar2;
  long lVar3;
  int local_30;
  
  local_30 = param_5;
  if (param_5 == 0) {
    local_30 = *(int *)(param_1 + 0x3c);
  }
  if (param_2 == 0) {
    uVar1 = htons(param_6);
    uVar2 = htons(param_4);
    lVar3 = FUN_00115770(param_1,param_3,uVar2,local_30,uVar1,0x1000);
    if (lVar3 == 0) {
      return 0xffffffff;
    }
  }
  else {
    uVar1 = htons(param_6);
    uVar2 = htons(param_4);
    lVar3 = FUN_0010a32a(param_1,param_3,uVar2,local_30,uVar1,0x1000);
    if (lVar3 == 0) {
      return 0xffffffff;
    }
  }
  return 0;
}



undefined8 FUN_00105165(long param_1,uint *param_2,int param_3)

{
  uint uVar1;
  uint32_t uVar2;
  undefined8 uVar3;
  long local_20;
  
  if (*param_2 == 0) {
    uVar1 = *(uint *)(param_1 + 0xc);
    uVar2 = htonl(0x204);
    *param_2 = uVar1 | uVar2 & ~*(uint *)(param_1 + 0x10);
  }
  if ((((*param_2 & *(uint *)(param_1 + 0x10)) == *(uint *)(param_1 + 0xc)) &&
      (*param_2 != *(uint *)(param_1 + 0x14))) && (*param_2 != *(uint *)(param_1 + 0x40))) {
    for (local_20 = *(long *)(param_1 + 0x80); local_20 != 0; local_20 = *(long *)(local_20 + 0x28))
    {
      if ((param_3 == *(int *)(local_20 + 0x14)) && (*param_2 == *(uint *)(local_20 + 0x10))) {
        return 0;
      }
    }
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}



undefined8 FUN_00105244(long param_1,undefined8 param_2,undefined4 *param_3,undefined4 param_4)

{
  char cVar1;
  uint16_t uVar2;
  undefined8 uVar3;
  
  cVar1 = FUN_00105165(param_1,param_3,param_4);
  if (cVar1 == '\x01') {
    uVar2 = htons((uint16_t)param_4);
    FUN_00106b19(param_1 + 0x80,param_2,*param_3,uVar2);
    uVar3 = 0;
  }
  else {
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



undefined8 FUN_001052b9(long param_1,undefined8 param_2,undefined4 *param_3,undefined4 param_4)

{
  char cVar1;
  uint16_t uVar2;
  undefined8 uVar3;
  
  cVar1 = FUN_00105165(param_1,param_3,param_4);
  if (cVar1 == '\x01') {
    uVar2 = htons((uint16_t)param_4);
    FUN_00106b75(param_1 + 0x80,param_2,*param_3,uVar2);
    uVar3 = 0;
  }
  else {
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



undefined8
FUN_0010532e(long param_1,undefined8 param_2,undefined8 param_3,undefined4 *param_4,
            undefined4 param_5)

{
  char cVar1;
  uint16_t uVar2;
  undefined8 uVar3;
  
  cVar1 = FUN_00105165(param_1,param_4,param_5);
  if (cVar1 == '\x01') {
    uVar2 = htons((uint16_t)param_5);
    FUN_00106a9c(param_1 + 0x80,param_2,param_3,*param_4,uVar2);
    uVar3 = 0;
  }
  else {
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



void FUN_001053ad(long param_1,undefined4 param_2,uint16_t param_3)

{
  uint16_t uVar1;
  
  uVar1 = htons(param_3);
  FUN_00106bd1(param_1 + 0x80,param_2,uVar1);
  return;
}



size_t FUN_001053ed(long param_1,void *param_2,size_t param_3,int param_4)

{
  int *piVar1;
  
  if ((*(int *)(param_1 + 0x10) == -1) && (*(long *)(param_1 + 0x18) != 0)) {
    (*(code *)**(undefined8 **)(param_1 + 0x18))
              (param_2,param_3,*(undefined8 *)(*(long *)(param_1 + 0x18) + 8));
  }
  else if (*(int *)(param_1 + 0x10) == -1) {
    piVar1 = __errno_location();
    *piVar1 = 9;
    param_3 = 0xffffffffffffffff;
  }
  else {
    param_3 = send(*(int *)(param_1 + 0x10),param_2,param_3,param_4);
  }
  return param_3;
}



undefined8 * FUN_0010548a(long param_1,int param_2,uint param_3)

{
  uint16_t uVar1;
  undefined8 *local_10;
  
  local_10 = *(undefined8 **)(param_1 + 0x1c0);
  while( true ) {
    if (local_10 == (undefined8 *)(param_1 + 0x1c0)) {
      return (undefined8 *)0x0;
    }
    if ((*(int *)((long)local_10 + 0x4c) == param_2) &&
       (uVar1 = htons(*(uint16_t *)((long)local_10 + 0x4a)), param_3 == uVar1)) break;
    local_10 = (undefined8 *)*local_10;
  }
  return local_10;
}



undefined8 FUN_00105501(undefined8 param_1,undefined4 param_2,undefined4 param_3)

{
  long lVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  undefined local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = FUN_0010548a(param_1,param_2,param_3);
  if ((lVar1 == 0) || ((*(uint *)(lVar1 + 0x14c) & 1) != 0)) {
    uVar2 = 0;
  }
  else if (((*(uint *)(lVar1 + 0x14c) & 0xc) == 4) &&
          (*(uint *)(lVar1 + 0x188) < *(uint *)(lVar1 + 0x18c) >> 1)) {
    uVar2 = FUN_0011398c(lVar1,local_38,0);
  }
  else {
    uVar2 = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar2;
}



void FUN_001055be(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                 undefined4 param_5)

{
  int iVar1;
  long lVar2;
  
  lVar2 = FUN_0010548a(param_1,param_2,param_3);
  if (lVar2 != 0) {
    iVar1 = FUN_00114126(lVar2,param_4,param_5);
    if (0 < iVar1) {
      FUN_00105b44(*(undefined8 *)(lVar2 + 0x150));
    }
  }
  return;
}



void FUN_00105632(long param_1,undefined8 param_2,ulong param_3)

{
  ulong uVar1;
  
  uVar1 = (*(code *)**(undefined8 **)(param_1 + 0x1768))
                    (param_2,param_3,*(undefined8 *)(param_1 + 6000));
  if ((long)uVar1 < 0) {
    g_log("Slirp",8,"Failed to send packet, ret: %ld",uVar1);
  }
  else if ((uVar1 < param_3) && ((DAT_001231c0 & 4) != 0)) {
    g_log("Slirp",0x80,"send_packet() didn\'t send all data: %ld < %lu",uVar1,param_3);
  }
  return;
}



int FUN_001056ea(long param_1,int param_2)

{
  uint16_t uVar1;
  undefined4 local_10;
  undefined4 local_c;
  
  local_10 = 0;
  for (local_c = 0; local_c < param_2 / 2; local_c = local_c + 1) {
    uVar1 = htons(*(uint16_t *)(param_1 + (long)local_c * 2));
    local_10 = local_10 + (uint)uVar1;
  }
  return -local_10;
}



undefined8 FUN_0010574d(long param_1)

{
  uint32_t uVar1;
  
  uVar1 = htonl(0xffffffff);
  *(uint32_t *)(param_1 + 0x14) = uVar1;
  uVar1 = htonl(0xffffffff);
  *(uint32_t *)(param_1 + 0x18) = uVar1;
  uVar1 = htonl(0xffffffff);
  *(uint32_t *)(param_1 + 0x1c) = uVar1;
  uVar1 = htonl(0xffffffff);
  *(uint32_t *)(param_1 + 0x20) = uVar1;
  uVar1 = htonl(0xffffffff);
  *(uint32_t *)(param_1 + 0x24) = uVar1;
  *(undefined *)(param_1 + 0x2e) = 0xff;
  *(undefined *)(param_1 + 0x2b) = 2;
  return 0;
}



undefined8 FUN_001057d1(long param_1)

{
  uint32_t uVar1;
  
  uVar1 = htonl(1);
  *(uint32_t *)(param_1 + 0x14) = uVar1;
  return 0;
}



undefined8 FUN_00105801(long param_1)

{
  *(undefined *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x17) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  *(undefined2 *)(param_1 + 0x1a) = 0;
  return 0;
}



// WARNING: Type propagation algorithm not settling

void FUN_0010583e(undefined8 param_1,long param_2)

{
  uint32_t uVar1;
  long in_FS_OFFSET;
  uint local_11c;
  int local_118;
  undefined *local_110;
  undefined local_e8 [6];
  undefined auStack_e2 [6];
  uint16_t local_dc;
  undefined4 local_da;
  char local_d6;
  undefined local_d5;
  uint16_t local_d4;
  uint16_t local_ca;
  uint16_t local_c8;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_110 = (undefined *)0x0;
  local_118 = 0x10;
  memset(local_e8,0,0xce);
  memset(local_e8,0xff,6);
  memset(auStack_e2,0xff,6);
  local_dc = htons(0x88f8);
  local_11c = 0;
  do {
    if (0x1d < local_11c) {
LAB_0010598d:
      local_da._0_1_ = *(undefined *)(param_2 + 0xe);
      local_da._1_1_ = 1;
      local_da._3_1_ = *(undefined *)(param_2 + 0x11);
      local_d6 = *(char *)(param_2 + 0x12) + -0x80;
      local_d5 = *(undefined *)(param_2 + 0x13);
      if (local_110 == (undefined *)0x0) {
        local_d4 = 0;
        local_ca = htons(2);
        local_c8 = htons(0x7fff);
      }
      else {
        local_d4 = htons((uint16_t)*(undefined4 *)(local_110 + 4));
        local_ca = htons(0);
        local_c8 = htons(0);
        if (*(long *)(local_110 + 8) != 0) {
          (**(code **)(local_110 + 8))(&local_da);
        }
        local_118 = *(int *)(local_110 + 4) + 0x10;
      }
      uVar1 = FUN_001056ea(&local_da,local_118);
      uVar1 = htonl(uVar1);
      *(uint32_t *)((long)&local_da + (long)local_118) = uVar1;
      FUN_00105632(param_1,local_e8,(long)(local_118 + 0x12));
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
        __stack_chk_fail();
      }
      return;
    }
    if ((uint)(byte)(&DAT_00122940)[(long)(int)local_11c * 0x10] == *(byte *)(param_2 + 0x12) + 0x80
       ) {
      local_110 = &DAT_00122940 + (long)(int)local_11c * 0x10;
      goto LAB_0010598d;
    }
    local_11c = local_11c + 1;
  } while( true );
}



int FUN_00105b44(long param_1)

{
  byte bVar1;
  undefined4 uVar2;
  long lVar3;
  void *__dest;
  long lVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  bool bVar10;
  bool bVar11;
  uint16_t uVar12;
  undefined2 uVar13;
  uint uVar14;
  uint32_t uVar15;
  uint uVar16;
  ulong uVar17;
  ulong uVar18;
  long lVar19;
  int iVar20;
  ulong uVar21;
  long in_FS_OFFSET;
  int local_ec;
  uint local_e8;
  undefined4 local_b0;
  undefined4 uStack_ac;
  undefined uStack_a7;
  undefined uStack_8f;
  undefined2 uStack_8a;
  undefined local_68;
  undefined local_67;
  uint16_t local_66;
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  lVar3 = *(long *)(param_1 + 0x70);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_output...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p",param_1);
  }
  if ((*(int *)(param_1 + 0xa8) == *(int *)(param_1 + 0x78)) &&
     (*(short *)(param_1 + 0x1c) <= *(short *)(param_1 + 0xb4))) {
    *(uint *)(param_1 + 0xac) = (uint)*(ushort *)(param_1 + 0x20);
  }
  do {
    uVar16 = *(int *)(param_1 + 0x7c) - *(int *)(param_1 + 0x78);
    uVar14 = *(uint *)(param_1 + 0x90);
    if (*(uint *)(param_1 + 0xac) <= *(uint *)(param_1 + 0x90)) {
      uVar14 = *(uint *)(param_1 + 0xac);
    }
    uVar21 = (ulong)uVar14;
    bVar1 = (&DAT_0011d330)[(int)*(short *)(param_1 + 0x10)];
    if ((DAT_001231c0 & 2) != 0) {
      g_log("Slirp",0x80," --- tcp_output flags = 0x%x",bVar1);
    }
    if (*(char *)(param_1 + 0x22) != '\0') {
      if (uVar21 == 0) {
        if (uVar16 < *(uint *)(lVar3 + 0x188)) {
          bVar1 = bVar1 & 0xfe;
        }
        uVar21 = 1;
      }
      else {
        *(undefined2 *)(param_1 + 0x14) = 0;
        *(undefined2 *)(param_1 + 0x1a) = 0;
      }
    }
    uVar17 = (ulong)*(uint *)(lVar3 + 0x188);
    if (uVar21 <= *(uint *)(lVar3 + 0x188)) {
      uVar17 = uVar21;
    }
    uVar17 = uVar17 - (long)(int)uVar16;
    if (((long)uVar17 < 0) && (uVar17 = 0, uVar21 == 0)) {
      *(undefined2 *)(param_1 + 0x12) = 0;
      *(undefined4 *)(param_1 + 0x7c) = *(undefined4 *)(param_1 + 0x78);
    }
    bVar10 = (long)(ulong)*(ushort *)(param_1 + 0x20) < (long)uVar17;
    if (bVar10) {
      uVar17 = (ulong)*(ushort *)(param_1 + 0x20);
    }
    if ((*(int *)(param_1 + 0x7c) + (int)uVar17) -
        (*(int *)(lVar3 + 0x188) + *(int *)(param_1 + 0x78)) < 0) {
      bVar1 = bVar1 & 0xfe;
    }
    uVar21 = (ulong)(uint)(*(int *)(lVar3 + 0x16c) - *(int *)(lVar3 + 0x168));
    if ((uVar17 == 0) ||
       ((((uVar17 != *(ushort *)(param_1 + 0x20) &&
          ((long)((long)(int)uVar16 + uVar17) < (long)(ulong)*(uint *)(lVar3 + 0x188))) &&
         (*(char *)(param_1 + 0x22) == '\0')) &&
        ((((long)uVar17 < (long)(ulong)(*(uint *)(param_1 + 0xc4) >> 1) ||
          (*(int *)(param_1 + 0xc4) == 0)) &&
         (-1 < *(int *)(param_1 + 0x7c) - *(int *)(param_1 + 0xa8))))))) {
      if (uVar21 != 0) {
        uVar18 = 0xffffL << (*(byte *)(param_1 + 0xcd) & 0x3f);
        if ((long)uVar21 <= (long)uVar18) {
          uVar18 = uVar21;
        }
        lVar19 = uVar18 - (uint)(*(int *)(param_1 + 0xa4) - *(int *)(param_1 + 0x98));
        if (((int)((uint)*(ushort *)(param_1 + 0x20) * 2) <= lVar19) ||
           ((long)(ulong)*(uint *)(lVar3 + 0x16c) <= lVar19 * 2)) goto LAB_00106028;
      }
      if ((((*(ushort *)(param_1 + 0x24) & 1) == 0) &&
          (((bVar1 & 6) == 0 && (*(int *)(param_1 + 0x80) - *(int *)(param_1 + 0x78) < 1)))) &&
         (((bVar1 & 1) == 0 ||
          (((*(ushort *)(param_1 + 0x24) & 0x10) != 0 &&
           (*(int *)(param_1 + 0x7c) != *(int *)(param_1 + 0x78))))))) {
        if ((*(int *)(lVar3 + 0x188) != 0) &&
           ((*(short *)(param_1 + 0x12) == 0 && (*(short *)(param_1 + 0x14) == 0)))) {
          *(undefined2 *)(param_1 + 0x1a) = 0;
          FUN_00106923(param_1);
        }
        local_ec = 0;
        goto LAB_001068fd;
      }
    }
LAB_00106028:
    local_e8 = 0;
    if (((bVar1 & 2) != 0) &&
       (*(undefined4 *)(param_1 + 0x7c) = *(undefined4 *)(param_1 + 0x8c),
       (*(ushort *)(param_1 + 0x24) & 8) == 0)) {
      local_68 = 2;
      local_67 = 4;
      uVar12 = FUN_0010ce01(param_1,0);
      local_66 = htons(uVar12);
      local_e8 = 4;
    }
    uVar14 = local_e8 + 0x44;
    bVar11 = (long)(ulong)(*(ushort *)(param_1 + 0x20) - local_e8) < (long)uVar17;
    if (bVar11) {
      uVar17 = (ulong)(*(ushort *)(param_1 + 0x20) - local_e8);
    }
    iVar20 = (int)uVar17;
    if (uVar17 == 0) {
      lVar19 = FUN_00110cac(*(undefined8 *)(lVar3 + 0x28));
      if (lVar19 == 0) {
        local_ec = 1;
        goto LAB_001068fd;
      }
      *(long *)(lVar19 + 0x30) = *(long *)(lVar19 + 0x30) + 0x10;
      *(uint *)(lVar19 + 0x38) = uVar14;
    }
    else {
      lVar19 = FUN_00110cac(*(undefined8 *)(lVar3 + 0x28));
      if (lVar19 == 0) {
        local_ec = 1;
        goto LAB_001068fd;
      }
      *(long *)(lVar19 + 0x30) = *(long *)(lVar19 + 0x30) + 0x10;
      *(uint *)(lVar19 + 0x38) = uVar14;
      FUN_00108ab9(lVar3 + 0x188,(long)(int)uVar16,(long)iVar20,
                   *(long *)(lVar19 + 0x30) + (ulong)uVar14);
      *(int *)(lVar19 + 0x38) = iVar20 + *(int *)(lVar19 + 0x38);
      if ((long)(int)uVar16 + uVar17 == (ulong)*(uint *)(lVar3 + 0x188)) {
        bVar1 = bVar1 | 8;
      }
    }
    __dest = *(void **)(lVar19 + 0x30);
    memcpy(__dest,(void *)(param_1 + 0x28),0x44);
    if ((((bVar1 & 1) != 0) && ((*(ushort *)(param_1 + 0x24) & 0x10) != 0)) &&
       (*(int *)(param_1 + 0x7c) == *(int *)(param_1 + 0xa8))) {
      *(int *)(param_1 + 0x7c) = *(int *)(param_1 + 0x7c) + -1;
    }
    if (((uVar17 == 0) && ((bVar1 & 3) == 0)) && (*(short *)(param_1 + 0x14) == 0)) {
      uVar15 = htonl(*(uint32_t *)(param_1 + 0xa8));
      *(uint32_t *)((long)__dest + 0x34) = uVar15;
    }
    else {
      uVar15 = htonl(*(uint32_t *)(param_1 + 0x7c));
      *(uint32_t *)((long)__dest + 0x34) = uVar15;
    }
    uVar15 = htonl(*(uint32_t *)(param_1 + 0x98));
    *(uint32_t *)((long)__dest + 0x38) = uVar15;
    if (local_e8 != 0) {
      memcpy((void *)((long)__dest + 0x44),&local_68,(ulong)local_e8);
      *(byte *)((long)__dest + 0x3c) =
           *(byte *)((long)__dest + 0x3c) & 0xf | (byte)((int)((ulong)local_e8 + 0x14 >> 2) << 4);
    }
    *(byte *)((long)__dest + 0x3d) = bVar1;
    if ((uVar21 < *(uint *)(lVar3 + 0x16c) >> 2) && (uVar21 < *(ushort *)(param_1 + 0x20))) {
      uVar21 = 0;
    }
    if (0xffffL << (*(byte *)(param_1 + 0xcd) & 0x3f) < (long)uVar21) {
      uVar21 = 0xffffL << (*(byte *)(param_1 + 0xcd) & 0x3f);
    }
    if ((long)uVar21 < (long)(ulong)(uint)(*(int *)(param_1 + 0xa4) - *(int *)(param_1 + 0x98))) {
      uVar21 = (ulong)(uint)(*(int *)(param_1 + 0xa4) - *(int *)(param_1 + 0x98));
    }
    uVar12 = htons((uint16_t)((long)uVar21 >> (*(byte *)(param_1 + 0xcd) & 0x3f)));
    *(uint16_t *)((long)__dest + 0x3e) = uVar12;
    if (*(int *)(param_1 + 0x80) - *(int *)(param_1 + 0x78) < 1) {
      *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0x78);
    }
    else {
      uVar2 = *(undefined4 *)(param_1 + 0x80);
      uVar15 = ntohl(*(uint32_t *)((long)__dest + 0x34));
      uVar12 = htons((short)uVar2 - (short)uVar15);
      *(uint16_t *)((long)__dest + 0x42) = uVar12;
      *(byte *)((long)__dest + 0x3d) = *(byte *)((long)__dest + 0x3d) | 0x20;
    }
    if (local_e8 + uVar17 != 0) {
      uVar12 = htons((short)uVar17 + (short)local_e8 + 0x14);
      *(uint16_t *)((long)__dest + 0x2e) = uVar12;
    }
    uVar13 = FUN_0010d634(lVar19,uVar14 + iVar20);
    *(undefined2 *)((long)__dest + 0x40) = uVar13;
    if ((*(char *)(param_1 + 0x22) == '\0') || (*(short *)(param_1 + 0x14) == 0)) {
      uVar2 = *(undefined4 *)(param_1 + 0x7c);
      if ((bVar1 & 3) != 0) {
        if ((bVar1 & 2) != 0) {
          *(int *)(param_1 + 0x7c) = *(int *)(param_1 + 0x7c) + 1;
        }
        if ((bVar1 & 1) != 0) {
          *(int *)(param_1 + 0x7c) = *(int *)(param_1 + 0x7c) + 1;
          *(ushort *)(param_1 + 0x24) = *(ushort *)(param_1 + 0x24) | 0x10;
        }
      }
      *(int *)(param_1 + 0x7c) = iVar20 + *(int *)(param_1 + 0x7c);
      if ((0 < *(int *)(param_1 + 0x7c) - *(int *)(param_1 + 0xa8)) &&
         (*(undefined4 *)(param_1 + 0xa8) = *(undefined4 *)(param_1 + 0x7c),
         *(short *)(param_1 + 0xb6) == 0)) {
        *(undefined2 *)(param_1 + 0xb6) = 1;
        *(undefined4 *)(param_1 + 0xb8) = uVar2;
      }
      if (((*(short *)(param_1 + 0x12) == 0) &&
          (*(int *)(param_1 + 0x7c) != *(int *)(param_1 + 0x78))) &&
         (*(undefined2 *)(param_1 + 0x12) = *(undefined2 *)(param_1 + 0x1c),
         *(short *)(param_1 + 0x14) != 0)) {
        *(undefined2 *)(param_1 + 0x14) = 0;
        *(undefined2 *)(param_1 + 0x1a) = 0;
      }
    }
    else if (0 < (iVar20 + *(int *)(param_1 + 0x7c)) - *(int *)(param_1 + 0xa8)) {
      *(int *)(param_1 + 0xa8) = iVar20 + *(int *)(param_1 + 0x7c);
    }
    *(uint *)(lVar19 + 0x38) = uVar14 + iVar20;
    lVar4 = *(long *)(lVar19 + 0x30);
    uVar5 = *(undefined8 *)(lVar4 + 8);
    uVar6 = *(undefined8 *)(lVar4 + 0x10);
    uVar7 = *(undefined8 *)(lVar4 + 0x18);
    uVar8 = *(undefined8 *)(lVar4 + 0x20);
    uVar9 = *(undefined8 *)(lVar4 + 0x28);
    if (*(short *)(lVar3 + 0x48) == 2) {
      *(long *)(lVar19 + 0x30) = *(long *)(lVar19 + 0x30) + 0x1c;
      *(int *)(lVar19 + 0x38) = *(int *)(lVar19 + 0x38) + -0x1c;
      lVar4 = *(long *)(lVar19 + 0x30);
      *(short *)(lVar4 + 2) = (short)*(undefined4 *)(lVar19 + 0x38);
      uStack_ac = (undefined4)((ulong)uVar5 >> 0x20);
      *(undefined4 *)(lVar4 + 0x10) = uStack_ac;
      local_b0 = (undefined4)uVar5;
      *(undefined4 *)(lVar4 + 0xc) = local_b0;
      uStack_a7 = (undefined)((ulong)uVar6 >> 8);
      *(undefined *)(lVar4 + 9) = uStack_a7;
      *(undefined *)(lVar4 + 8) = 0x40;
      *(undefined *)(lVar4 + 1) = *(undefined *)(lVar3 + 0x148);
      local_ec = FUN_001196c1(lVar3,lVar19);
    }
    else if (*(short *)(lVar3 + 0x48) == 10) {
      *(long *)(lVar19 + 0x30) = *(long *)(lVar19 + 0x30) + 8;
      *(int *)(lVar19 + 0x38) = *(int *)(lVar19 + 0x38) + -8;
      lVar4 = *(long *)(lVar19 + 0x30);
      uStack_8a = (undefined2)((ulong)uVar9 >> 0x30);
      *(undefined2 *)(lVar4 + 4) = uStack_8a;
      *(undefined8 *)(lVar4 + 0x18) = uVar7;
      *(undefined8 *)(lVar4 + 0x20) = uVar8;
      *(undefined8 *)(lVar4 + 8) = uVar5;
      *(undefined8 *)(lVar4 + 0x10) = uVar6;
      uStack_8f = (undefined)((ulong)uVar9 >> 8);
      *(undefined *)(lVar4 + 6) = uStack_8f;
      local_ec = FUN_00107b40(lVar3,lVar19,0);
    }
    else {
      g_assertion_message_expr
                ("Slirp",
                 "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_output.c"
                 ,0x1e1,"tcp_output",0);
    }
    if (local_ec != 0) goto LAB_001068fd;
    if ((0 < (long)uVar21) &&
       (0 < ((int)uVar21 + *(int *)(param_1 + 0x98)) - *(int *)(param_1 + 0xa4))) {
      *(int *)(param_1 + 0xa4) = (int)uVar21 + *(int *)(param_1 + 0x98);
    }
    *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(param_1 + 0x98);
    *(ushort *)(param_1 + 0x24) = *(ushort *)(param_1 + 0x24) & 0xfffc;
  } while (bVar11 || bVar10);
  local_ec = 0;
LAB_001068fd:
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return local_ec;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00106923(long param_1)

{
  *(short *)(param_1 + 0x14) =
       (short)((int)*(short *)(param_1 + 0xbe) + (int)(*(short *)(param_1 + 0xbc) >> 2) >> 1) *
       (short)*(undefined4 *)(&DAT_0011e280 + (long)(int)*(short *)(param_1 + 0x1a) * 4);
  if (*(short *)(param_1 + 0x14) < 10) {
    *(undefined2 *)(param_1 + 0x14) = 10;
  }
  else if (0x78 < *(short *)(param_1 + 0x14)) {
    *(undefined2 *)(param_1 + 0x14) = 0x78;
  }
  if (*(short *)(param_1 + 0x1a) < 0xc) {
    *(short *)(param_1 + 0x1a) = *(short *)(param_1 + 0x1a) + 1;
  }
  return;
}



void FUN_001069db(int param_1)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 1;
  setsockopt(param_1,1,2,&local_14,4);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_00106a33(long *param_1,long *param_2)

{
  *param_1 = *param_2;
  *param_2 = (long)param_1;
  param_1[1] = (long)param_2;
  *(long **)(*param_1 + 8) = param_1;
  return;
}



void FUN_00106a6a(long *param_1)

{
  *(long *)(*param_1 + 8) = param_1[1];
  *(long *)param_1[1] = *param_1;
  param_1[1] = 0;
  return;
}



undefined8 *
FUN_00106a9c(long *param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
            undefined4 param_5)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)g_malloc0_n(1,0x30);
  *puVar1 = param_2;
  puVar1[1] = param_3;
  *(undefined4 *)((long)puVar1 + 0x14) = param_5;
  *(undefined4 *)(puVar1 + 2) = param_4;
  puVar1[5] = *param_1;
  *param_1 = (long)puVar1;
  return puVar1;
}



long FUN_00106b19(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = FUN_00106a9c(param_1,0,0,param_3,param_4);
  uVar2 = g_strdup(param_2);
  *(undefined8 *)(lVar1 + 0x18) = uVar2;
  return lVar1;
}



long FUN_00106b75(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = FUN_00106a9c(param_1,0,0,param_3,param_4);
  uVar2 = g_strdup(param_2);
  *(undefined8 *)(lVar1 + 0x20) = uVar2;
  return lVar1;
}



undefined8 FUN_00106bd1(long *param_1,int param_2,int param_3)

{
  long lVar1;
  long *local_20;
  
  local_20 = param_1;
  while( true ) {
    if (*local_20 == 0) {
      return 0xffffffff;
    }
    lVar1 = *local_20;
    if ((*(int *)(lVar1 + 0x10) == param_2) && (param_3 == *(int *)(lVar1 + 0x14))) break;
    local_20 = (long *)(*local_20 + 0x28);
  }
  *local_20 = *(long *)(lVar1 + 0x28);
  g_free(*(undefined8 *)(lVar1 + 0x18));
  g_free(lVar1);
  return 0;
}



undefined8 FUN_00106c62(int *param_1)

{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  socklen_t local_44;
  int local_40;
  int local_3c;
  sockaddr local_38;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_38.sa_data[6] = '\0';
  local_38.sa_data[7] = '\0';
  local_38.sa_data[8] = '\0';
  local_38.sa_data[9] = '\0';
  local_38.sa_data[10] = '\0';
  local_38.sa_data[0xb] = '\0';
  local_38.sa_data[0xc] = '\0';
  local_38.sa_data[0xd] = '\0';
  local_38.sa_family = 2;
  local_38.sa_data[0] = '\0';
  local_38.sa_data[1] = '\0';
  local_38.sa_data[2] = '\0';
  local_38.sa_data[3] = '\0';
  local_38.sa_data[4] = '\0';
  local_38.sa_data[5] = '\0';
  local_44 = 0x10;
  param_1[1] = -1;
  local_40 = FUN_001081c9(2,1,0);
  if ((((-1 < local_40) && (iVar1 = bind(local_40,&local_38,local_44), -1 < iVar1)) &&
      (iVar1 = listen(local_40,1), -1 < iVar1)) &&
     (iVar1 = getsockname(local_40,&local_38,&local_44), -1 < iVar1)) {
    iVar1 = FUN_001081c9(2,1,0);
    param_1[1] = iVar1;
    if (-1 < param_1[1]) {
      do {
        local_3c = connect(param_1[1],&local_38,local_44);
        if (-1 < local_3c) break;
        piVar2 = __errno_location();
      } while (*piVar2 == 4);
      if (-1 < local_3c) {
        do {
          iVar1 = accept(local_40,&local_38,&local_44);
          *param_1 = iVar1;
          if (-1 < *param_1) break;
          piVar2 = __errno_location();
        } while (*piVar2 == 4);
        if (-1 < *param_1) {
          close(local_40);
          uVar3 = 0;
          goto LAB_00106e3c;
        }
      }
    }
  }
  piVar2 = __errno_location();
  pcVar4 = strerror(*piVar2);
  g_log("Slirp",8,"slirp_socketpair(): %s",pcVar4);
  if (-1 < local_40) {
    close(local_40);
  }
  if (-1 < param_1[1]) {
    close(param_1[1]);
  }
  uVar3 = 0xffffffff;
LAB_00106e3c:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00106e57(void)

{
  setsid();
  return;
}



void FUN_00106e6f(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined4 param_8,
                 undefined4 param_9,undefined4 param_10,undefined8 param_11)

{
  g_spawn_async_with_fds
            (param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
             param_11);
  return;
}



undefined8 FUN_00106ec9(long param_1,undefined8 param_2)

{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  undefined4 local_30;
  undefined4 local_2c;
  long local_28;
  undefined8 local_20;
  int local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0;
  local_30 = 0;
  local_20 = 0;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"fork_exec...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," ex = %p",param_2);
  }
  iVar1 = FUN_00106c62(&local_18);
  if (iVar1 < 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = g_shell_parse_argv(param_2,&local_30,&local_20,&local_28);
    if (iVar1 == 0) {
      g_log("Slirp",8,"fork_exec invalid command: %s\nerror: %s",param_2,
            *(undefined8 *)(local_28 + 8));
      g_error_free(local_28);
      uVar2 = 0;
    }
    else {
      FUN_00106e6f(0,local_20,0,4,FUN_00106e57,0,0,local_14,local_14,local_14,&local_28);
      g_strfreev(local_20);
      if (local_28 == 0) {
        *(int *)(param_1 + 0x10) = local_18;
        close(local_14);
        FUN_001069db(*(undefined4 *)(param_1 + 0x10));
        local_2c = 1;
        setsockopt(*(int *)(param_1 + 0x10),1,10,&local_2c,4);
        FUN_001080a5(*(undefined4 *)(param_1 + 0x10));
        (**(code **)(*(long *)(*(long *)(param_1 + 0x28) + 0x1768) + 0x30))
                  (*(undefined4 *)(param_1 + 0x10),*(undefined8 *)(*(long *)(param_1 + 0x28) + 6000)
                  );
        uVar2 = 1;
      }
      else {
        g_log("Slirp",8,"fork_exec: %s",*(undefined8 *)(local_28 + 8));
        g_error_free(local_28);
        close(local_18);
        close(local_14);
        uVar2 = 0;
      }
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar2;
}



undefined8 FUN_0010715b(long param_1,undefined8 param_2)

{
  int __fd;
  int iVar1;
  ulong uVar2;
  undefined8 uVar3;
  int *piVar4;
  char *pcVar5;
  long in_FS_OFFSET;
  sockaddr local_88 [7];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"open_unix...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," unixpath = %s",param_2);
  }
  memset(local_88,0,0x6e);
  local_88[0].sa_family = 1;
  uVar2 = g_strlcpy(local_88[0].sa_data,param_2,0x6c);
  if (uVar2 < 0x6c) {
    __fd = FUN_001081c9(1,1,0);
    if (__fd < 0) {
      piVar4 = __errno_location();
      pcVar5 = strerror(*piVar4);
      g_log("Slirp",8,"open_unix(): %s",pcVar5);
      uVar3 = 0;
    }
    else {
      iVar1 = connect(__fd,local_88,0x6e);
      if (iVar1 < 0) {
        piVar4 = __errno_location();
        pcVar5 = strerror(*piVar4);
        g_log("Slirp",8,"open_unix(): %s",pcVar5);
        close(__fd);
        uVar3 = 0;
      }
      else {
        *(int *)(param_1 + 0x10) = __fd;
        FUN_001080a5(*(undefined4 *)(param_1 + 0x10));
        (**(code **)(*(long *)(*(long *)(param_1 + 0x28) + 0x1768) + 0x30))
                  (*(undefined4 *)(param_1 + 0x10),*(undefined8 *)(*(long *)(param_1 + 0x28) + 6000)
                  );
        uVar3 = 1;
      }
    }
  }
  else {
    g_log("Slirp",8,"Bad unix path: %s",param_2);
    uVar3 = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar3;
}



void FUN_001073ba(long param_1)

{
  in_addr __in;
  undefined4 uVar1;
  undefined4 uVar2;
  uint16_t uVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  uint16_t local_da;
  in_addr local_d8;
  socklen_t local_d4;
  undefined8 *local_d0;
  char *local_c8;
  undefined8 local_c0;
  undefined local_b8 [16];
  char *local_a8 [4];
  char *local_88;
  char *local_80;
  char *local_78;
  char *local_70;
  char *local_68;
  char *local_60;
  char *local_58;
  undefined local_48 [24];
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  local_c0 = g_string_new(0);
  local_a8[0] = "CLOSED";
  local_a8[1] = "LISTEN";
  local_a8[2] = "SYN_SENT";
  local_a8[3] = "SYN_RCVD";
  local_88 = "ESTABLISHED";
  local_80 = "CLOSE_WAIT";
  local_78 = "FIN_WAIT_1";
  local_70 = "CLOSING";
  local_68 = "LAST_ACK";
  local_60 = "FIN_WAIT_2";
  local_58 = "TIME_WAIT";
  g_string_append_printf
            (local_c0,
             "  Protocol[State]    FD  Source Address  Port   Dest. Address  Port RecvQ SendQ\n");
  for (local_d0 = *(undefined8 **)(param_1 + 0x1c0); local_d0 != (undefined8 *)(param_1 + 0x1c0);
      local_d0 = (undefined8 *)*local_d0) {
    if ((*(uint *)((long)local_d0 + 0x14c) & 0x1000) == 0) {
      if (local_d0[0x2a] == 0) {
        local_c8 = "NONE";
      }
      else {
        local_c8 = local_a8[(int)*(short *)(local_d0[0x2a] + 0x10)];
      }
    }
    else {
      local_c8 = "HOST_FORWARD";
    }
    if ((*(uint *)((long)local_d0 + 0x14c) & 0x3000) == 0) {
      local_b8._4_4_ = *(in_addr_t *)((long)local_d0 + 0xcc);
      local_b8._2_2_ = *(uint16_t *)((long)local_d0 + 0xca);
      local_d8.s_addr = *(in_addr_t *)((long)local_d0 + 0x4c);
      local_da = *(uint16_t *)((long)local_d0 + 0x4a);
    }
    else {
      local_d4 = 0x10;
      getsockname(*(int *)(local_d0 + 2),(sockaddr *)local_b8,&local_d4);
      local_d8.s_addr = *(in_addr_t *)((long)local_d0 + 0xcc);
      local_da = *(uint16_t *)((long)local_d0 + 0xca);
    }
    FUN_00108442(local_48,0x14,"  TCP[%s]",local_c8);
    uVar3 = ntohs(local_b8._2_2_);
    if (local_b8._4_4_ == 0) {
      pcVar4 = "*";
    }
    else {
      pcVar4 = inet_ntoa((in_addr)local_b8._4_4_);
    }
    g_string_append_printf
              (local_c0,"%-19s %3d %15s %5d ",local_48,*(undefined4 *)(local_d0 + 2),pcVar4,uVar3);
    uVar1 = *(undefined4 *)(local_d0 + 0x31);
    uVar2 = *(undefined4 *)(local_d0 + 0x2d);
    uVar3 = ntohs(local_da);
    pcVar4 = inet_ntoa(local_d8);
    g_string_append_printf(local_c0,"%15s %5d %5d %5d\n",pcVar4,uVar3,uVar2,uVar1);
  }
  for (local_d0 = *(undefined8 **)(param_1 + 0x378); local_d0 != (undefined8 *)(param_1 + 0x378);
      local_d0 = (undefined8 *)*local_d0) {
    if ((*(uint *)((long)local_d0 + 0x14c) & 0x1000) == 0) {
      FUN_00108442(local_48,0x14,"  UDP[%d sec]",
                   (uint)(*(int *)(local_d0 + 0x2b) - DAT_001231c8) / 1000);
      local_b8._4_4_ = *(in_addr_t *)((long)local_d0 + 0xcc);
      local_b8._2_2_ = *(uint16_t *)((long)local_d0 + 0xca);
      local_d8.s_addr = *(in_addr_t *)((long)local_d0 + 0x4c);
      local_da = *(uint16_t *)((long)local_d0 + 0x4a);
    }
    else {
      FUN_00108442(local_48,0x14,"  UDP[HOST_FORWARD]");
      local_d4 = 0x10;
      getsockname(*(int *)(local_d0 + 2),(sockaddr *)local_b8,&local_d4);
      local_d8.s_addr = *(in_addr_t *)((long)local_d0 + 0xcc);
      local_da = *(uint16_t *)((long)local_d0 + 0xca);
    }
    uVar3 = ntohs(local_b8._2_2_);
    if (local_b8._4_4_ == 0) {
      pcVar4 = "*";
    }
    else {
      pcVar4 = inet_ntoa((in_addr)local_b8._4_4_);
    }
    g_string_append_printf
              (local_c0,"%-19s %3d %15s %5d ",local_48,*(undefined4 *)(local_d0 + 2),pcVar4,uVar3);
    uVar1 = *(undefined4 *)(local_d0 + 0x31);
    uVar2 = *(undefined4 *)(local_d0 + 0x2d);
    uVar3 = ntohs(local_da);
    pcVar4 = inet_ntoa(local_d8);
    g_string_append_printf(local_c0,"%15s %5d %5d %5d\n",pcVar4,uVar3,uVar2,uVar1);
  }
  for (local_d0 = *(undefined8 **)(param_1 + 0x528); local_d0 != (undefined8 *)(param_1 + 0x528);
      local_d0 = (undefined8 *)*local_d0) {
    FUN_00108442(local_48,0x14,"  ICMP[%d sec]",
                 (uint)(*(int *)(local_d0 + 0x2b) - DAT_001231c8) / 1000);
    local_b8._4_4_ = *(in_addr_t *)((long)local_d0 + 0xcc);
    __in.s_addr = *(in_addr_t *)((long)local_d0 + 0x4c);
    if (local_b8._4_4_ == 0) {
      pcVar4 = "*";
    }
    else {
      pcVar4 = inet_ntoa((in_addr)local_b8._4_4_);
    }
    g_string_append_printf
              (local_c0,"%-19s %3d %15s  -    ",local_48,*(undefined4 *)(local_d0 + 2),pcVar4);
    uVar1 = *(undefined4 *)(local_d0 + 0x31);
    uVar2 = *(undefined4 *)(local_d0 + 0x2d);
    pcVar4 = inet_ntoa(__in);
    g_string_append_printf(local_c0,"%15s  -    %5d %5d\n",pcVar4,uVar2,uVar1);
  }
  g_string_free(local_c0,0);
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



int FUN_00107a81(long param_1,short param_2)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined8 local_10;
  
  local_18 = 0;
  local_10 = (sockaddr *)0x0;
  local_14 = 0;
  if ((param_2 == 2) && (*(long *)(*(long *)(param_1 + 0x28) + 0x1778) != 0)) {
    local_10 = *(sockaddr **)(*(long *)(param_1 + 0x28) + 0x1778);
    local_14 = 0x10;
  }
  else if ((param_2 == 10) && (*(long *)(*(long *)(param_1 + 0x28) + 0x1780) != 0)) {
    local_10 = *(sockaddr **)(*(long *)(param_1 + 0x28) + 0x1780);
    local_14 = 0x1c;
  }
  if (local_10 != (sockaddr *)0x0) {
    local_18 = bind(*(int *)(param_1 + 0x10),local_10,local_14);
  }
  return local_18;
}



undefined8 FUN_00107b40(undefined8 param_1,long param_2,int param_3)

{
  byte *pbVar1;
  
  pbVar1 = *(byte **)(param_2 + 0x30);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ip6_output...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_2);
  }
  *pbVar1 = *pbVar1 & 0xf | 0x60;
  pbVar1[7] = 0xff;
  *pbVar1 = *pbVar1 & 0xf0;
  pbVar1[1] = pbVar1[1] & 0xf;
  pbVar1[1] = pbVar1[1] & 0xf0;
  pbVar1[2] = 0;
  pbVar1[3] = 0;
  if (param_3 == 0) {
    FUN_0010d15e(param_1,param_2);
  }
  else {
    FUN_00104c4c(*(undefined8 *)(param_2 + 0x40),param_2);
  }
  return 0;
}



void FUN_00107c71(long param_1,in_addr param_2,undefined *param_3)

{
  uint uVar1;
  uint uVar2;
  long lVar3;
  char *pcVar4;
  int local_18;
  
  uVar1 = *(uint *)(param_1 + 0x10);
  uVar2 = *(uint *)(param_1 + 0xc);
  lVar3 = param_1 + 0x1408;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"arp_table_add...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    pcVar4 = inet_ntoa(param_2);
    g_log("Slirp",0x80," ip = %s",pcVar4);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," hw addr = %02x:%02x:%02x:%02x:%02x:%02x",*param_3,param_3[1],param_3[2],
          param_3[3],param_3[4],param_3[5]);
  }
  if (((param_2.s_addr != 0) && (param_2.s_addr != 0xffffffff)) &&
     (param_2.s_addr != (uVar2 | ~uVar1))) {
    for (local_18 = 0; local_18 < 0x10; local_18 = local_18 + 1) {
      if (param_2.s_addr == *(in_addr_t *)((long)local_18 * 0x1c + lVar3 + 0xe)) {
        memcpy((void *)((long)local_18 * 0x1c + lVar3 + 8),param_3,6);
        return;
      }
    }
    *(in_addr_t *)(lVar3 + (long)*(int *)(param_1 + 0x15c8) * 0x1c + 0xe) = param_2.s_addr;
    memcpy((void *)((long)*(int *)(param_1 + 0x15c8) * 0x1c + lVar3 + 8),param_3,6);
    *(int *)(param_1 + 0x15c8) = (*(int *)(param_1 + 0x15c8) + 1) % 0x10;
  }
  return;
}



undefined8 FUN_00107ec0(long param_1,in_addr param_2,undefined *param_3)

{
  uint uVar1;
  uint uVar2;
  char *pcVar3;
  undefined8 uVar4;
  int local_18;
  
  uVar1 = *(uint *)(param_1 + 0x10);
  uVar2 = *(uint *)(param_1 + 0xc);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"arp_table_search...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    pcVar3 = inet_ntoa(param_2);
    g_log("Slirp",0x80," ip = %s",pcVar3);
  }
  if (((param_2.s_addr == 0) || (param_2.s_addr == 0xffffffff)) ||
     (param_2.s_addr == (uVar2 | ~uVar1))) {
    memset(param_3,0xff,6);
    uVar4 = 1;
  }
  else {
    for (local_18 = 0; local_18 < 0x10; local_18 = local_18 + 1) {
      if (param_2.s_addr == *(in_addr_t *)((long)local_18 * 0x1c + param_1 + 0x1408 + 0xe)) {
        memcpy(param_3,(void *)((long)local_18 * 0x1c + param_1 + 0x1408 + 8),6);
        if ((DAT_001231c0 & 1) != 0) {
          g_log("Slirp",0x80," found hw addr = %02x:%02x:%02x:%02x:%02x:%02x",*param_3,param_3[1],
                param_3[2],param_3[3],param_3[4],param_3[5]);
        }
        return 1;
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}



void FUN_001080a5(int param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = fcntl(param_1,3);
  if (uVar1 == 0xffffffff) {
                    // WARNING: Subroutine does not return
    __assert_fail("f != -1",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/util.c"
                  ,0x34,"slirp_set_nonblock");
  }
  iVar2 = fcntl(param_1,4,(ulong)(uVar1 | 0x800));
  if (iVar2 == -1) {
                    // WARNING: Subroutine does not return
    __assert_fail("f != -1",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/util.c"
                  ,0x36,"slirp_set_nonblock");
  }
  return;
}



void FUN_00108137(int param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = fcntl(param_1,1);
  if (uVar1 == 0xffffffff) {
                    // WARNING: Subroutine does not return
    __assert_fail("f != -1",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/util.c"
                  ,0x42,"slirp_set_cloexec");
  }
  iVar2 = fcntl(param_1,2,(ulong)(uVar1 | 1));
  if (iVar2 == -1) {
                    // WARNING: Subroutine does not return
    __assert_fail("f != -1",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/util.c"
                  ,0x44,"slirp_set_cloexec");
  }
  return;
}



int FUN_001081c9(int param_1,uint param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = socket(param_1,param_2 | 0x80000,param_3);
  if (((iVar1 == -1) && (piVar2 = __errno_location(), *piVar2 == 0x16)) &&
     (iVar1 = socket(param_1,param_2,param_3), -1 < iVar1)) {
    FUN_00108137(iVar1);
  }
  return iVar1;
}



void FUN_0010823b(char *param_1,int param_2,char *param_3)

{
  char *local_30;
  char *local_10;
  
  local_30 = param_3;
  local_10 = param_1;
  if (0 < param_2) {
    while( true ) {
      if ((*local_30 == '\0') || (param_1 + (long)param_2 + -1 <= local_10)) break;
      *local_10 = *local_30;
      local_30 = local_30 + 1;
      local_10 = local_10 + 1;
    }
    *local_10 = '\0';
  }
  return;
}



int FUN_001082ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  iVar1 = g_vsnprintf(param_1,param_2,param_3,param_4);
  if (iVar1 < 0) {
    piVar2 = __errno_location();
    uVar3 = g_strerror(*piVar2);
    g_log("Slirp",4,"g_vsnprintf() failed: %s",uVar3);
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  return iVar1;
}



ulong FUN_0010831e(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                  undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                  undefined8 param_9,ulong param_10,undefined8 param_11,undefined8 param_12,
                  undefined8 param_13,undefined8 param_14)

{
  char in_AL;
  int iVar1;
  ulong uVar2;
  long in_FS_OFFSET;
  undefined4 local_d8;
  undefined4 local_d4;
  undefined *local_d0;
  undefined *local_c8;
  long local_c0;
  undefined local_b8 [24];
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  undefined8 local_18;
  
  if (in_AL != '\0') {
    local_88 = param_1;
    local_78 = param_2;
    local_68 = param_3;
    local_58 = param_4;
    local_48 = param_5;
    local_38 = param_6;
    local_28 = param_7;
    local_18 = param_8;
  }
  local_c0 = *(long *)(in_FS_OFFSET + 0x28);
  local_d8 = 0x18;
  local_d4 = 0x30;
  local_d0 = &stack0x00000008;
  local_c8 = local_b8;
  local_a0 = param_12;
  local_98 = param_13;
  local_90 = param_14;
  iVar1 = FUN_001082ac(param_9,param_10,param_11,&local_d8);
  if (param_10 <= (ulong)(long)iVar1) {
    g_log("Slirp",8,"slirp_fmt() truncation");
  }
  uVar2 = (long)iVar1;
  if (param_10 <= (ulong)(long)iVar1) {
    uVar2 = param_10;
  }
  if (local_c0 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar2;
}



int FUN_00108442(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                long param_9,ulong param_10,undefined8 param_11,undefined8 param_12,
                undefined8 param_13,undefined8 param_14)

{
  char in_AL;
  long in_FS_OFFSET;
  int local_dc;
  undefined4 local_d8;
  undefined4 local_d4;
  undefined *local_d0;
  undefined *local_c8;
  long local_c0;
  undefined local_b8 [24];
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  undefined8 local_18;
  
  if (in_AL != '\0') {
    local_88 = param_1;
    local_78 = param_2;
    local_68 = param_3;
    local_58 = param_4;
    local_48 = param_5;
    local_38 = param_6;
    local_28 = param_7;
    local_18 = param_8;
  }
  local_c0 = *(long *)(in_FS_OFFSET + 0x28);
  local_d8 = 0x18;
  local_d4 = 0x30;
  local_d0 = &stack0x00000008;
  local_c8 = local_b8;
  local_a0 = param_12;
  local_98 = param_13;
  local_90 = param_14;
  local_dc = FUN_001082ac(param_9,param_10,param_11,&local_d8);
  if ((ulong)(long)local_dc < param_10) {
    local_dc = local_dc + 1;
  }
  else {
    g_log("Slirp",8,"slirp_fmt0() truncation");
    if (param_10 != 0) {
      *(undefined *)(param_9 + (param_10 - 1)) = 0;
    }
    local_dc = (int)param_10;
  }
  if (local_c0 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return local_dc;
}



void FUN_0010858d(long param_1)

{
  g_free(*(undefined8 *)(param_1 + 0x18));
  return;
}



undefined8 FUN_001085b0(uint *param_1,ulong param_2)

{
  uint uVar1;
  undefined8 uVar2;
  ulong local_28;
  
  uVar1 = param_1[1];
  if (*param_1 < param_2) {
    g_warn_message("Slirp",
                   "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/sbuf.c"
                   ,0x13,"sbdrop","num <= sb->sb_cc");
  }
  local_28 = param_2;
  if (*param_1 < param_2) {
    local_28 = (ulong)*param_1;
  }
  *param_1 = *param_1 - (int)local_28;
  *(ulong *)(param_1 + 4) = *(long *)(param_1 + 4) + local_28;
  if ((ulong)param_1[1] + *(long *)(param_1 + 6) <= *(ulong *)(param_1 + 4)) {
    *(ulong *)(param_1 + 4) = *(long *)(param_1 + 4) - (ulong)param_1[1];
  }
  if ((*param_1 < uVar1 >> 1) && ((ulong)(long)(int)(uVar1 >> 1) <= *param_1 + local_28)) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_001086bd(undefined4 *param_1,undefined8 param_2)

{
  undefined8 uVar1;
  
  uVar1 = g_realloc(*(undefined8 *)(param_1 + 6),param_2);
  *(undefined8 *)(param_1 + 6) = uVar1;
  *(undefined8 *)(param_1 + 4) = *(undefined8 *)(param_1 + 6);
  *(undefined8 *)(param_1 + 2) = *(undefined8 *)(param_1 + 4);
  *param_1 = 0;
  param_1[1] = (int)param_2;
  return;
}



void FUN_0010872a(long param_1,long param_2)

{
  int local_c;
  
  local_c = 0;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"sbappend...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_2);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m->m_len = %d",*(undefined4 *)(param_2 + 0x38));
  }
  if (*(int *)(param_2 + 0x38) < 1) {
    FUN_00110e00(param_2);
  }
  else if (*(int *)(param_1 + 0x40) == 0) {
    if (*(int *)(param_1 + 0x168) == 0) {
      local_c = FUN_001053ed(param_1,*(undefined8 *)(param_2 + 0x30),(long)*(int *)(param_2 + 0x38),
                             0);
    }
    if (local_c < 1) {
      FUN_00108917(param_1 + 0x168,param_2);
    }
    else if (local_c != *(int *)(param_2 + 0x38)) {
      *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) - local_c;
      *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + (long)local_c;
      FUN_00108917(param_1 + 0x168,param_2);
    }
    FUN_00110e00(param_2);
  }
  else {
    FUN_00108917(param_1 + 0x168,param_2);
    FUN_00110e00(param_2);
    FUN_001143fb(param_1);
  }
  return;
}



void FUN_00108917(int *param_1,long param_2)

{
  int iVar1;
  int local_14;
  int local_10;
  
  iVar1 = *(int *)(param_2 + 0x38);
  if (*(ulong *)(param_1 + 2) < *(ulong *)(param_1 + 4)) {
    local_14 = (int)*(undefined8 *)(param_1 + 4) - (int)*(undefined8 *)(param_1 + 2);
    if (iVar1 < local_14) {
      local_14 = iVar1;
    }
    memcpy(*(void **)(param_1 + 2),*(void **)(param_2 + 0x30),(long)local_14);
  }
  else {
    local_14 = ((int)*(undefined8 *)(param_1 + 6) + param_1[1]) - (int)*(undefined8 *)(param_1 + 2);
    if (iVar1 < local_14) {
      local_14 = iVar1;
    }
    memcpy(*(void **)(param_1 + 2),*(void **)(param_2 + 0x30),(long)local_14);
    iVar1 = iVar1 - local_14;
    if (iVar1 != 0) {
      local_10 = (int)*(undefined8 *)(param_1 + 4) - (int)*(undefined8 *)(param_1 + 6);
      if (iVar1 < local_10) {
        local_10 = iVar1;
      }
      memcpy(*(void **)(param_1 + 6),(void *)(*(long *)(param_2 + 0x30) + (long)local_14),
             (long)local_10);
      local_14 = local_14 + local_10;
    }
  }
  *param_1 = *param_1 + local_14;
  *(long *)(param_1 + 2) = *(long *)(param_1 + 2) + (long)local_14;
  if ((ulong)(uint)param_1[1] + *(long *)(param_1 + 6) <= *(ulong *)(param_1 + 2)) {
    *(ulong *)(param_1 + 2) = *(long *)(param_1 + 2) - (ulong)(uint)param_1[1];
  }
  return;
}



void FUN_00108ab9(uint *param_1,long param_2,ulong param_3,void *param_4)

{
  size_t local_28;
  void *local_10;
  
  if ((ulong)*param_1 < param_3 + param_2) {
    g_assertion_message_expr
              ("Slirp",
               "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/sbuf.c"
               ,0x96,"sbcopy","len + off <= sb->sb_cc");
  }
  local_10 = (void *)(param_2 + *(long *)(param_1 + 4));
  if ((void *)((ulong)param_1[1] + *(long *)(param_1 + 6)) <= local_10) {
    local_10 = (void *)((long)local_10 - (ulong)param_1[1]);
  }
  if (local_10 < *(void **)(param_1 + 2)) {
    memcpy(param_4,local_10,param_3);
  }
  else {
    local_28 = ((ulong)param_1[1] + *(long *)(param_1 + 6)) - (long)local_10;
    if (param_3 < local_28) {
      local_28 = param_3;
    }
    memcpy(param_4,local_10,local_28);
    if (param_3 - local_28 != 0) {
      memcpy((void *)((long)param_4 + local_28),*(void **)(param_1 + 6),param_3 - local_28);
    }
  }
  return;
}



ulong FUN_00108bf0(long param_1,long param_2)

{
  ulong uVar1;
  ulong uVar2;
  char *local_38;
  char *local_30;
  ulong local_28;
  
  uVar2 = *(ulong *)(param_1 + 0x18);
  uVar1 = *(ulong *)(param_2 + 0x18);
  local_38 = (char *)(uVar2 + *(long *)(param_1 + 0x10));
  local_30 = (char *)(uVar1 + *(long *)(param_2 + 0x10));
  if (uVar1 <= uVar2) {
    uVar2 = uVar1;
  }
  local_28 = 0;
  while( true ) {
    if (uVar2 <= local_28) {
      return local_28;
    }
    local_38 = local_38 + -1;
    local_30 = local_30 + -1;
    if (*local_38 != *local_30) break;
    local_28 = local_28 + 1;
  }
  return local_28;
}



undefined8 FUN_00108c8d(long param_1,long param_2)

{
  byte bVar1;
  byte bVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  undefined8 uVar6;
  
  uVar3 = *(ulong *)(param_1 + 0x18);
  uVar4 = *(ulong *)(param_2 + 0x18);
  lVar5 = FUN_00108bf0(param_1,param_2);
  bVar1 = *(byte *)((uVar3 - lVar5) + *(long *)(param_1 + 0x10));
  bVar2 = *(byte *)((uVar4 - lVar5) + *(long *)(param_2 + 0x10));
  if (bVar1 < bVar2) {
    uVar6 = 0xffffffff;
  }
  else if (bVar2 < bVar1) {
    uVar6 = 1;
  }
  else if (uVar3 < uVar4) {
    uVar6 = 0xffffffff;
  }
  else if (uVar4 < uVar3) {
    uVar6 = 1;
  }
  else {
    uVar6 = 0;
  }
  return uVar6;
}



ulong FUN_00108d5b(long param_1,undefined8 param_2)

{
  long lVar1;
  ulong uVar2;
  byte *local_28;
  
  lVar1 = FUN_00108bf0(param_1,param_2);
  for (local_28 = *(byte **)(param_1 + 0x10);
      (*local_28 != 0 &&
      (local_28 < (byte *)((*(long *)(param_1 + 0x18) - lVar1) + *(long *)(param_1 + 0x10))));
      local_28 = local_28 + (ulong)*local_28 + 1) {
  }
  uVar2 = *(long *)(param_1 + 0x18) - ((long)local_28 - *(long *)(param_1 + 0x10));
  if (uVar2 < 3) {
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_00108e15(long param_1,ulong param_2)

{
  undefined8 *puVar1;
  ulong local_28;
  undefined8 *local_20;
  undefined8 *local_18;
  
  for (local_28 = 0; local_28 < param_2; local_28 = local_28 + 1) {
    local_20 = (undefined8 *)(param_1 + local_28 * 0x28);
    local_18 = *(undefined8 **)(param_1 + local_28 * 0x28);
    while (local_20[4] == 0) {
      puVar1 = (undefined8 *)*local_18;
      *local_18 = local_20;
      local_20[4] = local_20[4] + 1;
      local_20 = local_18;
      local_18 = puVar1;
    }
  }
  return;
}



void FUN_00108ed5(long param_1,char *param_2)

{
  char cVar1;
  undefined *local_28;
  undefined *local_20;
  char *local_18;
  ulong local_10;
  
  local_28 = *(undefined **)(param_1 + 0x10);
  local_10 = 0;
  if (*(long *)(param_1 + 0x18) == 0) {
LAB_00108fc8:
    g_log("Slirp",0x10,"failed to parse domain name \'%s\'\n",param_2);
    *(undefined8 *)(param_1 + 0x18) = 0;
  }
  else {
    *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 1;
    local_20 = local_28;
    local_18 = param_2;
    do {
      cVar1 = *local_18;
      if ((cVar1 == '.') || (cVar1 == '\0')) {
        local_10 = (long)local_20 - (long)local_28;
        if (((local_10 == 0) && (cVar1 == '.')) || (0x3f < local_10)) goto LAB_00108fc8;
        *local_28 = (char)local_10;
        local_28 = local_20 + 1;
      }
      else {
        local_20[1] = cVar1;
      }
      local_20 = local_20 + 1;
      local_18 = local_18 + 1;
    } while (cVar1 != '\0');
    if (local_10 != 0) {
      *local_28 = 0;
      *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 1;
    }
  }
  return;
}



void FUN_00108ffd(long param_1,long param_2,ulong param_3)

{
  long lVar1;
  ulong uVar2;
  bool bVar3;
  long local_30;
  long local_28;
  long local_20;
  ulong local_18;
  
  lVar1 = param_1;
  local_28 = param_1;
  do {
    local_30 = lVar1;
    if (*(ulong *)(local_30 + 0x10) < *(ulong *)(local_28 + 0x10)) {
      local_28 = local_30;
    }
    lVar1 = local_30 + 0x28;
    bVar3 = param_2 != local_30;
    local_30 = param_1;
  } while (bVar3);
  for (; local_30 != param_2; local_30 = local_30 + 0x28) {
    if (param_3 != *(ulong *)(local_30 + 0x20)) {
      local_18 = 0xffffffffffffffff;
      for (local_20 = local_30;
          (local_20 != param_2 && (uVar2 = *(ulong *)(local_20 + 0x20), param_3 < uVar2));
          local_20 = local_20 + 0x28) {
        if (uVar2 < local_18) {
          local_18 = uVar2;
        }
      }
      FUN_00108ffd(local_30,local_20,local_18);
      local_30 = local_20;
      if (local_20 == param_2) break;
    }
  }
  local_30 = param_1;
  if (param_3 != 0) {
    do {
      if ((local_30 != local_28) && (*(long *)(local_30 + 8) == 0)) {
        *(long *)(local_30 + 8) = local_28;
        *(ulong *)(local_30 + 0x20) = param_3;
      }
      bVar3 = param_2 != local_30;
      local_30 = local_30 + 0x28;
    } while (bVar3);
  }
  return;
}



long FUN_00109152(long *param_1,ulong param_2)

{
  void *pvVar1;
  long lVar2;
  long lVar3;
  ulong uVar4;
  void *local_38;
  ulong local_30;
  
  pvVar1 = *(void **)(*param_1 + 0x10);
  local_38 = pvVar1;
  for (local_30 = 0; local_30 < param_2; local_30 = local_30 + 1) {
    lVar2 = param_1[local_30 * 5];
    lVar3 = *(long *)(lVar2 + 8);
    if ((lVar3 != 0) &&
       (uVar4 = (*(long *)(lVar3 + 0x18) - *(long *)(lVar2 + 0x20)) +
                (*(long *)(lVar3 + 0x10) - (long)pvVar1), uVar4 < 0x3fff)) {
      *(long *)(lVar2 + 0x18) = (*(long *)(lVar2 + 0x18) - *(long *)(lVar2 + 0x20)) + 2;
      *(char *)(*(long *)(lVar2 + 0x18) + -1 + *(long *)(lVar2 + 0x10)) = (char)uVar4;
      *(byte *)(*(long *)(lVar2 + 0x18) + -2 + *(long *)(lVar2 + 0x10)) = (byte)(uVar4 >> 8) | 0xc0;
    }
    if (local_38 != *(void **)(lVar2 + 0x10)) {
      memmove(local_38,*(void **)(lVar2 + 0x10),*(size_t *)(lVar2 + 0x18));
      *(void **)(lVar2 + 0x10) = local_38;
    }
    local_38 = (void *)((long)local_38 + *(long *)(lVar2 + 0x18));
  }
  return (long)local_38 - (long)pvVar1;
}



undefined8 FUN_001092c3(long param_1,long param_2)

{
  long lVar1;
  uint uVar2;
  ulong __nmemb;
  undefined8 uVar3;
  void *__base;
  size_t sVar4;
  long lVar5;
  ulong local_70;
  long local_68;
  long local_60;
  long local_58;
  ulong local_50;
  long local_48;
  long local_40;
  
  local_48 = 0;
  uVar2 = g_strv_length(param_2);
  __nmemb = (ulong)uVar2;
  if (__nmemb == 0) {
    uVar3 = 0xfffffffe;
  }
  else {
    __base = (void *)g_malloc(__nmemb * 0x28);
    for (local_50 = 0; local_50 < __nmemb; local_50 = local_50 + 1) {
      sVar4 = strlen(*(char **)(param_2 + local_50 * 8));
      local_48 = local_48 + sVar4 + 2;
      *(void **)((long)__base + local_50 * 0x28) = (void *)((long)__base + local_50 * 0x28);
      *(size_t *)((long)__base + local_50 * 0x28 + 0x18) = sVar4;
      *(undefined8 *)((long)__base + local_50 * 0x28 + 0x20) = 0;
      *(undefined8 *)((long)__base + local_50 * 0x28 + 8) = 0;
    }
    lVar5 = g_malloc(local_48 + ((local_48 + 0xfeU) / 0xff) * 2);
    local_40 = lVar5;
    for (local_50 = 0; local_50 < __nmemb; local_50 = local_50 + 1) {
      *(long *)((long)__base + local_50 * 0x28 + 0x10) = local_40;
      FUN_00108ed5((void *)((long)__base + local_50 * 0x28),*(undefined8 *)(param_2 + local_50 * 8))
      ;
      local_40 = local_40 + *(long *)((long)__base + local_50 * 0x28 + 0x18);
    }
    if (local_40 == lVar5) {
      g_free(__base);
      g_free(lVar5);
      uVar3 = 0xffffffff;
    }
    else {
      qsort(__base,__nmemb,0x28,FUN_00108c8d);
      FUN_00108e15(__base,__nmemb);
      for (local_50 = 1; local_50 < __nmemb; local_50 = local_50 + 1) {
        uVar3 = FUN_00108d5b((long)__base + local_50 * 0x28 + -0x28,
                             (void *)(local_50 * 0x28 + (long)__base));
        *(undefined8 *)((long)__base + local_50 * 0x28 + -8) = uVar3;
      }
      FUN_00108ffd(__base,__nmemb * 0x28 + -0x28 + (long)__base,0);
      local_60 = FUN_00109152(__base,__nmemb);
      local_70 = (local_60 + 0xfeU) / 0xff;
      local_68 = (local_70 - 1) * 0xff;
      local_58 = local_68 + local_70 * 2;
      lVar1 = local_60 + local_70 * 2;
      while( true ) {
        if (local_70 == 0) break;
        memmove((void *)(lVar5 + local_58),(void *)(lVar5 + local_68),local_60 - local_68);
        *(undefined *)(lVar5 + local_58 + -2) = 0x77;
        *(char *)(lVar5 + local_58 + -1) = (char)(local_60 - local_68);
        local_60 = local_68;
        local_68 = local_68 + -0xff;
        local_58 = local_58 + -0x101;
        local_70 = local_70 - 1;
      }
      g_free(__base);
      *(long *)(param_1 + 0x1b0) = lVar5;
      *(long *)(param_1 + 0x1a8) = lVar1;
      uVar3 = 0;
    }
  }
  return uVar3;
}



void FUN_00109792(int param_1)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 1;
  setsockopt(param_1,1,2,&local_14,4);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_001097ea(long param_1)

{
  *(long *)(param_1 + 0x380) = param_1 + 0x378;
  *(undefined8 *)(param_1 + 0x378) = *(undefined8 *)(param_1 + 0x380);
  *(long *)(param_1 + 0x520) = param_1 + 0x378;
  return;
}



void FUN_0010983b(long param_1)

{
  undefined8 local_18;
  
  local_18 = *(undefined8 **)(param_1 + 0x378);
  while (local_18 != (undefined8 *)(param_1 + 0x378)) {
    local_18 = (undefined8 *)*local_18;
    FUN_0010a15c(*(undefined8 *)(param_1 + 0x378));
  }
  return;
}



void FUN_00109896(long param_1,uint param_2)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  long lVar3;
  undefined8 *__s;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined uVar6;
  uint16_t uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  char *pcVar12;
  long in_FS_OFFSET;
  uint local_fc;
  long local_f0;
  undefined8 local_d8;
  undefined2 local_b8;
  undefined2 local_b6;
  undefined4 local_b4;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  lVar3 = *(long *)(param_1 + 0x40);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"udp_input...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," iphlen = %d",param_2);
  }
  local_fc = param_2;
  if (0x14 < param_2) {
    FUN_00116e28(param_1,0);
    local_fc = 0x14;
  }
  __s = *(undefined8 **)(param_1 + 0x30);
  puVar1 = (undefined2 *)((long)__s + (long)(int)local_fc);
  uVar7 = ntohs(puVar1[2]);
  uVar8 = (uint)uVar7;
  if (uVar8 == *(ushort *)((long)__s + 2)) {
LAB_001099ef:
    uVar4 = *__s;
    uVar5 = __s[1];
    uVar2 = *(undefined4 *)(__s + 2);
    local_d8._2_2_ = (short)((ulong)uVar4 >> 0x10);
    local_d8._2_2_ = local_d8._2_2_ + (short)local_fc;
    local_d8._4_4_ = (undefined4)((ulong)uVar4 >> 0x20);
    local_d8._0_2_ = (undefined2)uVar4;
    if (puVar1[3] != 0) {
      memset(__s,0,8);
      *(undefined *)(__s + 1) = 0;
      *(undefined2 *)((long)__s + 10) = puVar1[2];
      iVar9 = FUN_0010d634(param_1,uVar8 + 0x14);
      if (iVar9 != 0) goto LAB_00109e5c;
    }
    local_b8 = 2;
    local_b4 = *(undefined4 *)((long)__s + 0xc);
    local_b6 = *puVar1;
    uVar7 = ntohs(puVar1[1]);
    if ((uVar7 == 0x43) &&
       ((*(int *)(__s + 2) == *(int *)(lVar3 + 0x14) || (*(int *)(__s + 2) == -1)))) {
      FUN_0011941c(param_1);
    }
    else {
      uVar7 = ntohs(puVar1[1]);
      if ((uVar7 == 0x45) && (*(int *)(__s + 2) == *(int *)(lVar3 + 0x14))) {
        *(long *)(param_1 + 0x30) = (long)(int)local_fc + *(long *)(param_1 + 0x30);
        *(uint *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) - local_fc;
        FUN_0011acec(&local_b8,param_1);
        *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) - (long)(int)local_fc;
        *(uint *)(param_1 + 0x38) = local_fc + *(int *)(param_1 + 0x38);
      }
      else if (*(int *)(lVar3 + 0x7c) == 0) {
        local_f0 = FUN_0011367c(lVar3 + 0x520,lVar3 + 0x378,&local_b8,0);
        if (local_f0 == 0) {
          local_f0 = FUN_0011376d(lVar3);
          iVar9 = FUN_0010a0ab(local_f0,2);
          if (iVar9 == -1) {
            if ((DAT_001231c0 & 2) != 0) {
              piVar11 = __errno_location();
              pcVar12 = strerror(*piVar11);
              piVar11 = __errno_location();
              g_log("Slirp",0x80," udp_attach errno = %d-%s",*piVar11,pcVar12);
            }
            FUN_0011385c(local_f0);
            goto LAB_00109e5c;
          }
          *(undefined2 *)(local_f0 + 200) = 2;
          *(undefined4 *)(local_f0 + 0xcc) = *(undefined4 *)((long)__s + 0xc);
          *(undefined2 *)(local_f0 + 0xca) = *puVar1;
          uVar6 = FUN_0010a1b9(local_f0);
          *(undefined *)(local_f0 + 0x148) = uVar6;
          if (*(char *)(local_f0 + 0x148) == '\0') {
            *(undefined *)(local_f0 + 0x148) = *(undefined *)((long)__s + 1);
          }
        }
        *(undefined2 *)(local_f0 + 0x48) = 2;
        *(undefined4 *)(local_f0 + 0x4c) = *(undefined4 *)(__s + 2);
        *(undefined2 *)(local_f0 + 0x4a) = puVar1[1];
        iVar9 = local_fc + 8;
        *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) - iVar9;
        *(long *)(param_1 + 0x30) = (long)iVar9 + *(long *)(param_1 + 0x30);
        iVar10 = FUN_001154c3(local_f0,param_1);
        if (iVar10 != -1) {
          FUN_00110e00(*(undefined8 *)(local_f0 + 0x30));
          *(int *)(param_1 + 0x38) = iVar9 + *(int *)(param_1 + 0x38);
          *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) - (long)iVar9;
          *__s = local_d8;
          __s[1] = uVar5;
          *(undefined4 *)(__s + 2) = uVar2;
          *(long *)(local_f0 + 0x30) = param_1;
          goto LAB_00109e64;
        }
        *(int *)(param_1 + 0x38) = iVar9 + *(int *)(param_1 + 0x38);
        *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) - (long)iVar9;
        *__s = local_d8;
        __s[1] = uVar5;
        *(undefined4 *)(__s + 2) = uVar2;
        if ((DAT_001231c0 & 2) != 0) {
          piVar11 = __errno_location();
          pcVar12 = strerror(*piVar11);
          piVar11 = __errno_location();
          g_log("Slirp",0x80,"udp tx errno = %d-%s",*piVar11,pcVar12);
        }
        piVar11 = __errno_location();
        pcVar12 = strerror(*piVar11);
        FUN_00117ef4(param_1,3,0,0,pcVar12);
      }
    }
  }
  else if (uVar8 <= *(ushort *)((long)__s + 2)) {
    FUN_00111173(param_1,uVar8 - *(ushort *)((long)__s + 2));
    *(uint16_t *)((long)__s + 2) = uVar7;
    goto LAB_001099ef;
  }
LAB_00109e5c:
  FUN_00110e00(param_1);
LAB_00109e64:
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined4 FUN_00109e86(undefined8 param_1,long param_2,long param_3,long param_4,undefined param_5)

{
  void *__s;
  uint16_t uVar1;
  undefined2 uVar2;
  undefined4 uVar3;
  char *pcVar4;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"udp_output...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_2);
  }
  if ((DAT_001231c0 & 1) != 0) {
    pcVar4 = inet_ntoa((in_addr)*(in_addr_t *)(param_3 + 4));
    g_log("Slirp",0x80," saddr = %s",pcVar4);
  }
  if ((DAT_001231c0 & 1) != 0) {
    pcVar4 = inet_ntoa((in_addr)*(in_addr_t *)(param_4 + 4));
    g_log("Slirp",0x80," daddr = %s",pcVar4);
  }
  *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + -0x1c;
  *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + 0x1c;
  __s = *(void **)(param_2 + 0x30);
  memset(__s,0,8);
  *(undefined *)((long)__s + 8) = 0;
  *(undefined *)((long)__s + 9) = 0x11;
  uVar1 = htons((short)*(undefined4 *)(param_2 + 0x38) - 0x14);
  *(uint16_t *)((long)__s + 10) = uVar1;
  *(undefined4 *)((long)__s + 0xc) = *(undefined4 *)(param_3 + 4);
  *(undefined4 *)((long)__s + 0x10) = *(undefined4 *)(param_4 + 4);
  *(undefined2 *)((long)__s + 0x14) = *(undefined2 *)(param_3 + 2);
  *(undefined2 *)((long)__s + 0x16) = *(undefined2 *)(param_4 + 2);
  *(undefined2 *)((long)__s + 0x18) = *(undefined2 *)((long)__s + 10);
  *(undefined2 *)((long)__s + 0x1a) = 0;
  uVar2 = FUN_0010d634(param_2,*(undefined4 *)(param_2 + 0x38));
  *(undefined2 *)((long)__s + 0x1a) = uVar2;
  if (*(short *)((long)__s + 0x1a) == 0) {
    *(undefined2 *)((long)__s + 0x1a) = 0xffff;
  }
  *(short *)((long)__s + 2) = (short)*(undefined4 *)(param_2 + 0x38);
  *(undefined *)((long)__s + 8) = 0x40;
  *(undefined *)((long)__s + 1) = param_5;
  uVar3 = FUN_001196c1(param_1,param_2);
  return uVar3;
}



undefined4 FUN_0010a0ab(long param_1,undefined2 param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_001081c9(param_2,2,0);
  *(undefined4 *)(param_1 + 0x10) = uVar1;
  if (*(int *)(param_1 + 0x10) != -1) {
    iVar2 = FUN_00107a81(param_1,param_2);
    if (iVar2 != 0) {
      close(*(int *)(param_1 + 0x10));
      *(undefined4 *)(param_1 + 0x10) = 0xffffffff;
      return 0xffffffff;
    }
    *(int *)(param_1 + 0x158) = DAT_001231c8 + 240000;
    FUN_00106a33(param_1,*(long *)(param_1 + 0x28) + 0x378);
  }
  return *(undefined4 *)(param_1 + 0x10);
}



void FUN_0010a15c(long param_1)

{
  (**(code **)(*(long *)(*(long *)(param_1 + 0x28) + 0x1768) + 0x38))
            (*(undefined4 *)(param_1 + 0x10),*(undefined8 *)(*(long *)(param_1 + 0x28) + 6000));
  close(*(int *)(param_1 + 0x10));
  FUN_0011385c(param_1);
  return;
}



undefined FUN_0010a1b9(long param_1)

{
  uint16_t uVar1;
  int local_c;
  
  local_c = 0;
  while( true ) {
    if ((&DAT_0011d97c)[(long)local_c * 6] == '\0') {
      return 0;
    }
    if (((*(short *)(&DAT_0011d97a + (long)local_c * 6) != 0) &&
        (uVar1 = ntohs(*(uint16_t *)(param_1 + 0x4a)),
        uVar1 == *(uint16_t *)(&DAT_0011d97a + (long)local_c * 6))) ||
       ((*(short *)(&DAT_0011d978 + (long)local_c * 6) != 0 &&
        (uVar1 = ntohs(*(uint16_t *)(param_1 + 0xca)),
        uVar1 == *(uint16_t *)(&DAT_0011d978 + (long)local_c * 6))))) break;
    local_c = local_c + 1;
  }
  if (*(char *)(*(long *)(param_1 + 0x28) + 0x1760) != '\0') {
    *(undefined *)(param_1 + 0x149) = (&DAT_0011d97d)[(long)local_c * 6];
  }
  return (&DAT_0011d97c)[(long)local_c * 6];
}



long FUN_0010a32a(long param_1,undefined4 param_2,undefined2 param_3,undefined4 param_4,
                 undefined2 param_5,uint param_6)

{
  undefined4 uVar1;
  int iVar2;
  long lVar3;
  long in_FS_OFFSET;
  socklen_t local_34;
  long local_30;
  sockaddr local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_34 = 0x10;
  memset(&local_28,0,0x10);
  local_30 = FUN_0011376d(param_1);
  uVar1 = FUN_001081c9(2,2,0);
  *(undefined4 *)(local_30 + 0x10) = uVar1;
  if (*(int *)(local_30 + 0x10) < 0) {
    FUN_0011385c(local_30);
    lVar3 = 0;
  }
  else {
    *(int *)(local_30 + 0x158) = DAT_001231c8 + 240000;
    FUN_00106a33(local_30,param_1 + 0x378);
    local_28.sa_family = 2;
    local_28.sa_data._0_2_ = param_3;
    local_28.sa_data._2_4_ = param_2;
    iVar2 = bind(*(int *)(local_30 + 0x10),&local_28,local_34);
    if (iVar2 < 0) {
      FUN_0010a15c(local_30);
      lVar3 = 0;
    }
    else {
      FUN_00109792(*(undefined4 *)(local_30 + 0x10));
      getsockname(*(int *)(local_30 + 0x10),&local_28,&local_34);
      *(ulong *)(local_30 + 0x48) =
           CONCAT44(local_28.sa_data._2_4_,CONCAT22(local_28.sa_data._0_2_,local_28.sa_family));
      *(undefined8 *)(local_30 + 0x50) = local_28.sa_data._6_8_;
      FUN_00116188(local_30);
      *(undefined2 *)(local_30 + 200) = 2;
      *(undefined2 *)(local_30 + 0xca) = param_5;
      *(undefined4 *)(local_30 + 0xcc) = param_4;
      if (param_6 != 0x200) {
        *(undefined4 *)(local_30 + 0x158) = 0;
      }
      *(uint *)(local_30 + 0x14c) = *(uint *)(local_30 + 0x14c) & 0xf000;
      *(uint *)(local_30 + 0x14c) = param_6 | 4 | *(uint *)(local_30 + 0x14c);
      lVar3 = local_30;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return lVar3;
}



byte FUN_0010a511(undefined8 *param_1,undefined8 *param_2,undefined8 param_3)

{
  long lVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  long lVar4;
  byte bVar5;
  int iVar6;
  undefined8 *puVar7;
  
  lVar1 = param_1[0xe];
  if (param_2 != (undefined8 *)0x0) {
    for (puVar7 = (undefined8 *)*param_1;
        (param_1 != puVar7 && (*(int *)((long)puVar7 + 0x44) - *(int *)((long)param_2 + 0x34) < 1));
        puVar7 = (undefined8 *)*puVar7) {
    }
    if (param_1 != (undefined8 *)puVar7[1]) {
      puVar7 = (undefined8 *)puVar7[1];
      iVar6 = (*(int *)((long)puVar7 + 0x44) + (uint)*(ushort *)((long)puVar7 + 0x3e)) -
              *(int *)((long)param_2 + 0x34);
      if (0 < iVar6) {
        if ((int)(uint)*(ushort *)((long)param_2 + 0x2e) <= iVar6) {
          FUN_00110e00(param_3);
          goto LAB_0010a6d1;
        }
        FUN_00111173(param_3,iVar6);
        *(short *)((long)param_2 + 0x2e) = *(short *)((long)param_2 + 0x2e) - (short)iVar6;
        *(int *)((long)param_2 + 0x34) = *(int *)((long)param_2 + 0x34) + iVar6;
      }
      puVar7 = (undefined8 *)*puVar7;
    }
    *param_2 = param_3;
    while( true ) {
      if ((param_1 == puVar7) ||
         (iVar6 = (*(int *)((long)param_2 + 0x34) + (uint)*(ushort *)((long)param_2 + 0x2e)) -
                  *(int *)((long)puVar7 + 0x44), iVar6 < 1)) goto LAB_0010a6b6;
      if (iVar6 < (int)(uint)*(ushort *)((long)puVar7 + 0x3e)) break;
      puVar7 = (undefined8 *)*puVar7;
      uVar3 = *(undefined8 *)(puVar7[1] + 0x10);
      FUN_00106a6a(puVar7[1]);
      FUN_00110e00(uVar3);
    }
    *(int *)((long)puVar7 + 0x44) = *(int *)((long)puVar7 + 0x44) + iVar6;
    *(short *)((long)puVar7 + 0x3e) = *(short *)((long)puVar7 + 0x3e) - (short)iVar6;
    FUN_00111173(puVar7[2],iVar6);
LAB_0010a6b6:
    FUN_00106a33(param_2 + -2,puVar7[1]);
  }
LAB_0010a6d1:
  if (*(short *)(param_1 + 2) < 4) {
    bVar5 = 0;
  }
  else {
    puVar2 = (undefined8 *)*param_1;
    puVar7 = puVar2 + 2;
    if ((param_1 == puVar2) || (*(int *)((long)puVar2 + 0x44) != *(int *)(param_1 + 0x13))) {
      bVar5 = 0;
    }
    else if ((*(short *)(param_1 + 2) == 3) && (*(short *)((long)puVar2 + 0x3e) != 0)) {
      bVar5 = 0;
    }
    else {
      do {
        *(uint *)(param_1 + 0x13) =
             (uint)*(ushort *)((long)puVar7 + 0x2e) + *(int *)(param_1 + 0x13);
        bVar5 = *(byte *)((long)puVar7 + 0x3d) & 1;
        FUN_00106a6a(puVar7 + -2);
        uVar3 = *puVar7;
        lVar4 = puVar7[-2];
        puVar7 = (undefined8 *)(lVar4 + 0x10);
        if ((*(uint *)(lVar1 + 0x14c) & 0x10) == 0) {
          if (*(char *)(lVar1 + 0x149) == '\0') {
            FUN_0010872a(lVar1,uVar3);
          }
          else {
            iVar6 = FUN_0010f408(lVar1,uVar3);
            if (iVar6 != 0) {
              FUN_0010872a(lVar1,uVar3);
            }
          }
        }
        else {
          FUN_00110e00(uVar3);
        }
      } while ((puVar7 != param_1) && (*(int *)(lVar4 + 0x44) == *(int *)(param_1 + 0x13)));
    }
  }
  return bVar5;
}



void FUN_0010a803(long param_1,uint param_2,long param_3,short param_4)

{
  ushort uVar1;
  short sVar2;
  uint uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  bool bVar8;
  undefined uVar9;
  byte bVar10;
  uint16_t uVar11;
  uint32_t uVar12;
  uint uVar13;
  int iVar14;
  int *piVar15;
  char *pcVar16;
  uint uVar17;
  uint uVar18;
  long *plVar19;
  void *unaff_R12;
  byte bVar20;
  uint uVar21;
  long in_FS_OFFSET;
  bool bVar22;
  uint local_234;
  long local_230;
  undefined local_221;
  int local_220;
  uint local_21c;
  uint local_218;
  int local_20c;
  uint local_208;
  int local_204;
  uint local_200;
  long local_1e8;
  long local_1e0;
  long local_1d8;
  long local_1d0;
  undefined8 local_198;
  undefined8 local_190;
  undefined4 local_188;
  undefined8 local_178;
  undefined8 local_170;
  undefined8 local_168;
  undefined8 local_160;
  undefined8 local_158;
  short local_148;
  undefined auStack_146 [6];
  undefined8 local_140;
  undefined8 local_138;
  undefined8 local_130;
  undefined8 local_128;
  undefined8 local_120;
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  short local_c8;
  undefined auStack_c6 [6];
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  local_1e8 = 0;
  local_220 = 0;
  plVar19 = (long *)0x0;
  bVar8 = false;
  local_20c = 0;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_input...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p  iphlen = %2d  inso = %p",param_1,param_2,param_3);
  }
  if (param_1 == 0) {
    local_1d0 = *(long *)(param_3 + 0x28);
    plVar19 = *(long **)(param_3 + 0x150);
    local_230 = *(long *)(param_3 + 0x30);
    *(undefined8 *)(param_3 + 0x30) = 0;
    unaff_R12 = *(void **)(param_3 + 0x38);
    local_208 = (uint)*(ushort *)((long)unaff_R12 + 0x3e);
    bVar20 = *(byte *)((long)unaff_R12 + 0x3d);
    local_1e0 = param_3;
    if ((*(uint *)(param_3 + 0x14c) & 1) != 0) {
      plVar19 = (long *)FUN_0010e72f(plVar19);
      goto LAB_0010c9e1;
    }
    goto LAB_0010bb05;
  }
  local_1d0 = *(long *)(param_1 + 0x40);
  puVar4 = *(undefined8 **)(param_1 + 0x30);
  puVar5 = *(undefined8 **)(param_1 + 0x30);
  if (param_4 == 2) {
    local_234 = param_2;
    if (0x14 < param_2) {
      FUN_00116e28(param_1,0);
      local_234 = 0x14;
    }
    uVar7 = *puVar4;
    uVar6 = puVar4[1];
    local_188 = *(undefined4 *)(puVar4 + 2);
    local_198._2_2_ = (short)((ulong)uVar7 >> 0x10);
    local_198._2_2_ = local_198._2_2_ + (short)local_234;
    local_198._4_4_ = (undefined4)((ulong)uVar7 >> 0x20);
    local_198._0_2_ = (undefined2)uVar7;
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0x1c;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0x1c;
    unaff_R12 = *(void **)(param_1 + 0x30);
    uVar1 = *(ushort *)((long)puVar4 + 2);
    local_21c = (uint)uVar1;
    *(undefined8 *)((long)unaff_R12 + -8) = 0;
    *(undefined8 *)((long)unaff_R12 + -0x10) = *(undefined8 *)((long)unaff_R12 + -8);
    memset(unaff_R12,0,8);
    memset((void *)((long)unaff_R12 + 8),0,0x24);
    *(undefined2 *)((long)unaff_R12 + 0x2c) = 0;
    local_190._4_4_ = (undefined4)((ulong)uVar6 >> 0x20);
    *(undefined4 *)((long)unaff_R12 + 8) = local_190._4_4_;
    *(undefined4 *)((long)unaff_R12 + 0xc) = local_188;
    local_190._1_1_ = (undefined)((ulong)uVar6 >> 8);
    *(undefined *)((long)unaff_R12 + 0x11) = local_190._1_1_;
    uVar11 = htons(uVar1);
    *(uint16_t *)((long)unaff_R12 + 0x2e) = uVar11;
    local_190 = uVar6;
  }
  else if (param_4 == 10) {
    uVar7 = *puVar5;
    local_170 = puVar5[1];
    local_168 = puVar5[2];
    local_160 = puVar5[3];
    local_158 = puVar5[4];
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -8;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 8;
    unaff_R12 = *(void **)(param_1 + 0x30);
    uVar1 = *(ushort *)((long)puVar5 + 4);
    local_21c = (uint)uVar1;
    *(undefined8 *)((long)unaff_R12 + -8) = 0;
    *(undefined8 *)((long)unaff_R12 + -0x10) = *(undefined8 *)((long)unaff_R12 + -8);
    memset(unaff_R12,0,8);
    memset((void *)((long)unaff_R12 + 8),0,0x24);
    *(undefined2 *)((long)unaff_R12 + 0x2c) = 0;
    *(undefined8 *)((long)unaff_R12 + 8) = local_170;
    *(undefined8 *)((long)unaff_R12 + 0x10) = local_168;
    *(undefined8 *)((long)unaff_R12 + 0x18) = local_160;
    *(undefined8 *)((long)unaff_R12 + 0x20) = local_158;
    local_178._6_1_ = (undefined)((ulong)uVar7 >> 0x30);
    *(undefined *)((long)unaff_R12 + 0x29) = local_178._6_1_;
    uVar11 = htons(uVar1);
    *(uint16_t *)((long)unaff_R12 + 0x2e) = uVar11;
    local_178 = uVar7;
  }
  else {
    g_assertion_message_expr
              ("Slirp",
               "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_input.c"
               ,0x134,"tcp_input",0);
  }
  iVar14 = FUN_0010d634(param_1,local_21c + 0x30);
  if (iVar14 != 0) {
LAB_0010caa5:
    FUN_00110e00(param_1);
    goto LAB_0010caba;
  }
  bVar10 = *(byte *)((long)unaff_R12 + 0x3c) >> 4;
  uVar17 = (uint)bVar10 * 4;
  if ((uVar17 < 0x14) || ((int)local_21c < (int)uVar17)) goto LAB_0010caa5;
  *(ushort *)((long)unaff_R12 + 0x2e) = (short)local_21c + (ushort)bVar10 * -4;
  if (0x14 < uVar17) {
    local_220 = uVar17 - 0x14;
    local_1e8 = *(long *)(param_1 + 0x30) + 0x44;
  }
  bVar20 = *(byte *)((long)unaff_R12 + 0x3d);
  uVar12 = ntohl(*(uint32_t *)((long)unaff_R12 + 0x34));
  *(uint32_t *)((long)unaff_R12 + 0x34) = uVar12;
  uVar12 = ntohl(*(uint32_t *)((long)unaff_R12 + 0x38));
  *(uint32_t *)((long)unaff_R12 + 0x38) = uVar12;
  uVar11 = ntohs(*(uint16_t *)((long)unaff_R12 + 0x3e));
  *(uint16_t *)((long)unaff_R12 + 0x3e) = uVar11;
  uVar11 = ntohs(*(uint16_t *)((long)unaff_R12 + 0x42));
  *(uint16_t *)((long)unaff_R12 + 0x42) = uVar11;
  *(long *)(param_1 + 0x30) = (long)(int)uVar17 + 0x30 + *(long *)(param_1 + 0x30);
  *(uint *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + (uint)bVar10 * -4 + -0x30;
  while( true ) {
    local_148 = param_4;
    local_c8 = param_4;
    if (param_4 == 2) {
                    // WARNING: Ignoring partial resolution of indirect
      auStack_146._2_4_ = *(undefined4 *)((long)unaff_R12 + 8);
                    // WARNING: Ignoring partial resolution of indirect
      auStack_146._0_2_ = *(undefined2 *)((long)unaff_R12 + 0x30);
                    // WARNING: Ignoring partial resolution of indirect
      auStack_c6._2_4_ = *(undefined4 *)((long)unaff_R12 + 0xc);
                    // WARNING: Ignoring partial resolution of indirect
      auStack_c6._0_2_ = *(undefined2 *)((long)unaff_R12 + 0x32);
    }
    else if (param_4 == 10) {
      local_140 = *(undefined8 *)((long)unaff_R12 + 8);
      local_138 = *(undefined8 *)((long)unaff_R12 + 0x10);
                    // WARNING: Ignoring partial resolution of indirect
      auStack_146._0_2_ = *(undefined2 *)((long)unaff_R12 + 0x30);
      local_c0 = *(undefined8 *)((long)unaff_R12 + 0x18);
      local_b8 = *(undefined8 *)((long)unaff_R12 + 0x20);
                    // WARNING: Ignoring partial resolution of indirect
      auStack_c6._0_2_ = *(undefined2 *)((long)unaff_R12 + 0x32);
    }
    else {
      g_assertion_message_expr
                ("Slirp",
                 "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_input.c"
                 ,0x172,"tcp_input",0);
    }
    local_1e0 = FUN_0011367c(local_1d0 + 0x368,local_1d0 + 0x1c0,&local_148,&local_c8);
    local_230 = param_1;
    if (local_1e0 == 0) {
      if (*(int *)(local_1d0 + 0x7c) != 0) {
        for (local_1d8 = *(long *)(local_1d0 + 0x80);
            (local_1d8 != 0 &&
            ((*(uint *)(local_1d8 + 0x14) != (uint)*(ushort *)((long)unaff_R12 + 0x32) ||
             (*(int *)((long)unaff_R12 + 0xc) != *(int *)(local_1d8 + 0x10)))));
            local_1d8 = *(long *)(local_1d8 + 0x28)) {
        }
        if (local_1d8 == 0) goto LAB_0010c9e1;
      }
      if ((bVar20 & 0x37) != 2) goto LAB_0010c9e1;
      local_1e0 = FUN_0011376d(local_1d0);
      FUN_0010f24f(local_1e0);
      FUN_001086bd(local_1e0 + 0x188,0x20000);
      FUN_001086bd(local_1e0 + 0x168,0x20000);
      *(ulong *)(local_1e0 + 200) = CONCAT62(auStack_146,local_148);
      *(undefined8 *)(local_1e0 + 0xd0) = local_140;
      *(undefined8 *)(local_1e0 + 0xd8) = local_138;
      *(undefined8 *)(local_1e0 + 0xe0) = local_130;
      *(undefined8 *)(local_1e0 + 0xe8) = local_128;
      *(undefined8 *)(local_1e0 + 0xf0) = local_120;
      *(undefined8 *)(local_1e0 + 0xf8) = local_118;
      *(undefined8 *)(local_1e0 + 0x100) = local_110;
      *(undefined8 *)(local_1e0 + 0x108) = local_108;
      *(undefined8 *)(local_1e0 + 0x110) = local_100;
      *(undefined8 *)(local_1e0 + 0x118) = local_f8;
      *(undefined8 *)(local_1e0 + 0x120) = local_f0;
      *(undefined8 *)(local_1e0 + 0x128) = local_e8;
      *(undefined8 *)(local_1e0 + 0x130) = local_e0;
      *(undefined8 *)(local_1e0 + 0x138) = local_d8;
      *(undefined8 *)(local_1e0 + 0x140) = local_d0;
      *(ulong *)(local_1e0 + 0x48) = CONCAT62(auStack_c6,local_c8);
      *(undefined8 *)(local_1e0 + 0x50) = local_c0;
      *(undefined8 *)(local_1e0 + 0x58) = local_b8;
      *(undefined8 *)(local_1e0 + 0x60) = local_b0;
      *(undefined8 *)(local_1e0 + 0x68) = local_a8;
      *(undefined8 *)(local_1e0 + 0x70) = local_a0;
      *(undefined8 *)(local_1e0 + 0x78) = local_98;
      *(undefined8 *)(local_1e0 + 0x80) = local_90;
      *(undefined8 *)(local_1e0 + 0x88) = local_88;
      *(undefined8 *)(local_1e0 + 0x90) = local_80;
      *(undefined8 *)(local_1e0 + 0x98) = local_78;
      *(undefined8 *)(local_1e0 + 0xa0) = local_70;
      *(undefined8 *)(local_1e0 + 0xa8) = local_68;
      *(undefined8 *)(local_1e0 + 0xb0) = local_60;
      *(undefined8 *)(local_1e0 + 0xb8) = local_58;
      *(undefined8 *)(local_1e0 + 0xc0) = local_50;
      uVar9 = FUN_0010f297(local_1e0);
      *(undefined *)(local_1e0 + 0x148) = uVar9;
      if (*(char *)(local_1e0 + 0x148) == '\0') {
        if (param_4 == 2) {
          *(undefined *)(local_1e0 + 0x148) = *(undefined *)((long)unaff_R12 + 1);
        }
        else if (param_4 != 10) {
          g_assertion_message_expr
                    ("Slirp",
                     "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_input.c"
                     ,0x1ac,"tcp_input",0);
        }
      }
      *(undefined2 *)(*(long *)(local_1e0 + 0x150) + 0x10) = 1;
    }
    if ((*(uint *)(local_1e0 + 0x14c) & 2) != 0) goto LAB_0010caa5;
    plVar19 = *(long **)(local_1e0 + 0x150);
    if (plVar19 == (long *)0x0) goto LAB_0010c9e1;
    if (*(short *)(plVar19 + 2) == 0) goto LAB_0010caa5;
    local_208 = (uint)*(ushort *)((long)unaff_R12 + 0x3e);
    *(undefined2 *)((long)plVar19 + 0xb4) = 0;
    if (DAT_001231cc == '\0') {
      *(undefined2 *)((long)plVar19 + 0x16) = 0x3840;
    }
    else {
      *(undefined2 *)((long)plVar19 + 0x16) = 0x96;
    }
    if ((local_1e8 != 0) && (*(short *)(plVar19 + 2) != 1)) {
      FUN_0010cadd(plVar19,local_1e8,local_220,unaff_R12);
    }
    if ((((*(short *)(plVar19 + 2) == 4) && ((bVar20 & 0x37) == 0x10)) &&
        (*(int *)((long)unaff_R12 + 0x34) == *(int *)(plVar19 + 0x13))) &&
       (((local_208 != 0 && (local_208 == *(uint *)(plVar19 + 0x12))) &&
        (*(int *)((long)plVar19 + 0x7c) == *(int *)(plVar19 + 0x15))))) {
      if (*(short *)((long)unaff_R12 + 0x2e) == 0) {
        if (((0 < *(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0xf)) &&
            (*(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0x15) < 1)) &&
           (*(uint *)(plVar19 + 0x12) <= *(uint *)((long)plVar19 + 0xac))) {
          if ((*(short *)((long)plVar19 + 0xb6) != 0) &&
             (0 < *(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0x17))) {
            FUN_0010cc41(plVar19,(int)*(short *)((long)plVar19 + 0xb6));
          }
          FUN_00116250(local_1e0,*(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0xf));
          *(undefined4 *)(plVar19 + 0xf) = *(undefined4 *)((long)unaff_R12 + 0x38);
          FUN_00110e00(param_1);
          if (*(int *)(plVar19 + 0xf) == *(int *)(plVar19 + 0x15)) {
            *(undefined2 *)((long)plVar19 + 0x12) = 0;
          }
          else if (*(short *)((long)plVar19 + 0x14) == 0) {
            *(undefined2 *)((long)plVar19 + 0x12) = *(undefined2 *)((long)plVar19 + 0x1c);
          }
          if (*(int *)(local_1e0 + 0x188) != 0) {
            FUN_00105b44(plVar19);
          }
          goto LAB_0010caba;
        }
      }
      else if (((*(int *)((long)unaff_R12 + 0x38) == *(int *)(plVar19 + 0xf)) &&
               (plVar19 == (long *)*plVar19)) &&
              ((uint)*(ushort *)((long)unaff_R12 + 0x2e) <=
               (uint)(*(int *)(local_1e0 + 0x16c) - *(int *)(local_1e0 + 0x168)))) {
        *(uint *)(plVar19 + 0x13) =
             (uint)*(ushort *)((long)unaff_R12 + 0x2e) + *(int *)(plVar19 + 0x13);
        if (*(char *)(local_1e0 + 0x149) == '\0') {
          FUN_0010872a(local_1e0,param_1);
        }
        else {
          iVar14 = FUN_0010f408(local_1e0,param_1);
          if (iVar14 != 0) {
            FUN_0010872a(local_1e0,param_1);
          }
        }
        *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
        FUN_00105b44(plVar19);
        goto LAB_0010caba;
      }
    }
    local_204 = *(int *)(local_1e0 + 0x16c) - *(int *)(local_1e0 + 0x168);
    if (local_204 < 0) {
      local_204 = 0;
    }
    iVar14 = *(int *)((long)plVar19 + 0xa4) - *(int *)(plVar19 + 0x13);
    if (iVar14 <= local_204) {
      iVar14 = local_204;
    }
    *(int *)((long)plVar19 + 0x94) = iVar14;
    if (*(short *)(plVar19 + 2) == 1) {
      if ((bVar20 & 4) != 0) goto LAB_0010caa5;
      if ((bVar20 & 0x10) != 0) goto LAB_0010c9e1;
      if ((bVar20 & 2) == 0) goto LAB_0010caa5;
      if (((param_4 != 2) ||
          ((*(uint *)(local_1e0 + 0x4c) & *(uint *)(local_1d0 + 0x10)) != *(uint *)(local_1d0 + 0xc)
          )) || ((*(int *)(local_1e0 + 0x4c) == *(int *)(local_1d0 + 0x14) ||
                 (*(int *)(local_1e0 + 0x4c) == *(int *)(local_1d0 + 0x40))))) goto LAB_0010b6df;
      local_1d8 = *(long *)(local_1d0 + 0x80);
      goto LAB_0010b6bb;
    }
    if (*(short *)(plVar19 + 2) == 2) {
      if (((bVar20 & 0x10) != 0) &&
         ((*(int *)((long)unaff_R12 + 0x38) - *(int *)((long)plVar19 + 0x8c) < 1 ||
          (0 < *(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0x15))))) goto LAB_0010c9e1;
      if ((bVar20 & 4) != 0) {
        if ((bVar20 & 0x10) != 0) {
          FUN_0010e65c(plVar19,0);
        }
        goto LAB_0010caa5;
      }
      if ((bVar20 & 2) == 0) goto LAB_0010caa5;
      if (((bVar20 & 0x10) != 0) &&
         (*(undefined4 *)(plVar19 + 0xf) = *(undefined4 *)((long)unaff_R12 + 0x38),
         *(int *)((long)plVar19 + 0x7c) - *(int *)(plVar19 + 0xf) < 0)) {
        *(undefined4 *)((long)plVar19 + 0x7c) = *(undefined4 *)(plVar19 + 0xf);
      }
      *(undefined2 *)((long)plVar19 + 0x12) = 0;
      *(undefined4 *)(plVar19 + 0x14) = *(undefined4 *)((long)unaff_R12 + 0x34);
      *(int *)(plVar19 + 0x13) = *(int *)(plVar19 + 0x14) + 1;
      *(undefined4 *)((long)plVar19 + 0xa4) = *(undefined4 *)(plVar19 + 0x13);
      *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
      if (((bVar20 & 0x10) == 0) || (*(int *)(plVar19 + 0xf) - *(int *)((long)plVar19 + 0x8c) < 1))
      {
        *(undefined2 *)(plVar19 + 2) = 3;
      }
      else {
        FUN_00115b94(local_1e0);
        *(undefined2 *)(plVar19 + 2) = 4;
        FUN_0010a511(plVar19,0,0);
        if (*(short *)((long)plVar19 + 0xb6) != 0) {
          FUN_0010cc41(plVar19,(int)*(short *)((long)plVar19 + 0xb6));
        }
      }
      goto LAB_0010bd1a;
    }
    local_218 = *(int *)(plVar19 + 0x13) - *(int *)((long)unaff_R12 + 0x34);
    if (0 < (int)local_218) {
      if ((bVar20 & 2) != 0) {
        *(int *)((long)unaff_R12 + 0x34) = *(int *)((long)unaff_R12 + 0x34) + 1;
        if (*(ushort *)((long)unaff_R12 + 0x42) < 2) {
          bVar20 = bVar20 & 0xdd;
        }
        else {
          *(short *)((long)unaff_R12 + 0x42) = *(short *)((long)unaff_R12 + 0x42) + -1;
          bVar20 = bVar20 & 0xfd;
        }
        local_218 = local_218 - 1;
      }
      if (((int)(uint)*(ushort *)((long)unaff_R12 + 0x2e) < (int)local_218) ||
         ((local_218 == *(ushort *)((long)unaff_R12 + 0x2e) && ((bVar20 & 1) == 0)))) {
        bVar20 = bVar20 & 0xfe;
        *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
        local_218 = (uint)*(ushort *)((long)unaff_R12 + 0x2e);
      }
      FUN_00111173(param_1,local_218);
      *(uint *)((long)unaff_R12 + 0x34) = local_218 + *(int *)((long)unaff_R12 + 0x34);
      *(short *)((long)unaff_R12 + 0x2e) = *(short *)((long)unaff_R12 + 0x2e) - (short)local_218;
      if ((int)local_218 < (int)(uint)*(ushort *)((long)unaff_R12 + 0x42)) {
        *(short *)((long)unaff_R12 + 0x42) = *(short *)((long)unaff_R12 + 0x42) - (short)local_218;
      }
      else {
        bVar20 = bVar20 & 0xdf;
        *(undefined2 *)((long)unaff_R12 + 0x42) = 0;
      }
    }
    if ((((*(uint *)(local_1e0 + 0x14c) & 1) != 0) && (5 < *(short *)(plVar19 + 2))) &&
       (*(short *)((long)unaff_R12 + 0x2e) != 0)) {
      plVar19 = (long *)FUN_0010e72f(plVar19);
      goto LAB_0010c9e1;
    }
    iVar14 = (*(int *)((long)unaff_R12 + 0x34) + (uint)*(ushort *)((long)unaff_R12 + 0x2e)) -
             (*(int *)((long)plVar19 + 0x94) + *(int *)(plVar19 + 0x13));
    if (iVar14 < 1) goto LAB_0010bfe2;
    if (iVar14 < (int)(uint)*(ushort *)((long)unaff_R12 + 0x2e)) goto LAB_0010bfaf;
    if ((((bVar20 & 2) == 0) || (*(short *)(plVar19 + 2) != 10)) ||
       (*(int *)((long)unaff_R12 + 0x34) - *(int *)(plVar19 + 0x13) < 1)) break;
    local_20c = *(int *)(plVar19 + 0x13) + 0x1f400;
    plVar19 = (long *)FUN_0010e72f(plVar19);
  }
  if ((*(int *)((long)plVar19 + 0x94) != 0) ||
     (*(int *)((long)unaff_R12 + 0x34) != *(int *)(plVar19 + 0x13))) goto LAB_0010c99c;
  *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
LAB_0010bfaf:
  FUN_00111173(param_1,-iVar14);
  *(short *)((long)unaff_R12 + 0x2e) = *(short *)((long)unaff_R12 + 0x2e) - (short)iVar14;
  bVar20 = bVar20 & 0xf6;
LAB_0010bfe2:
  if ((bVar20 & 4) != 0) {
    iVar14 = (int)*(short *)(plVar19 + 2);
    if (iVar14 == 10) {
LAB_0010c02e:
      FUN_0010e72f(plVar19);
      goto LAB_0010caa5;
    }
    if (iVar14 < 0xb) {
      if (iVar14 == 9) {
LAB_0010c01b:
        *(undefined2 *)(plVar19 + 2) = 0;
        FUN_0010e72f(plVar19);
        goto LAB_0010caa5;
      }
      if (iVar14 < 10) {
        if (iVar14 < 7) {
          if (2 < iVar14) goto LAB_0010c01b;
        }
        else if (iVar14 - 7U < 2) goto LAB_0010c02e;
      }
    }
  }
  if ((bVar20 & 2) != 0) {
    plVar19 = (long *)FUN_0010e65c(plVar19,0);
LAB_0010c9e1:
    if ((bVar20 & 0x10) == 0) {
      if ((bVar20 & 2) != 0) {
        *(short *)((long)unaff_R12 + 0x2e) = *(short *)((long)unaff_R12 + 0x2e) + 1;
      }
      FUN_0010dde3(plVar19,unaff_R12,local_230,
                   *(int *)((long)unaff_R12 + 0x34) + (uint)*(ushort *)((long)unaff_R12 + 0x2e),0,
                   0x14,param_4);
    }
    else {
      FUN_0010dde3(plVar19,unaff_R12,local_230,0,*(undefined4 *)((long)unaff_R12 + 0x38),4,param_4);
    }
    goto LAB_0010caba;
  }
  if ((bVar20 & 0x10) == 0) goto LAB_0010caa5;
  iVar14 = (int)*(short *)(plVar19 + 2);
  if (iVar14 == 3) {
    if ((0 < *(int *)(plVar19 + 0xf) - *(int *)((long)unaff_R12 + 0x38)) ||
       (0 < *(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0x15))) goto LAB_0010c9e1;
    *(undefined2 *)(plVar19 + 2) = 4;
    *(undefined4 *)(plVar19 + 0xf) = *(undefined4 *)((long)unaff_R12 + 0x38);
    if ((*(uint *)(local_1e0 + 0x14c) & 0x80) == 0) {
      FUN_00115b94(local_1e0);
    }
    else {
      iVar14 = FUN_00110985(local_1e0);
      if (iVar14 == 1) {
        FUN_00115b94(local_1e0);
        *(uint *)(local_1e0 + 0x14c) = *(uint *)(local_1e0 + 0x14c) & 0xffffff7f;
      }
      else if (iVar14 == 2) {
        *(uint *)(local_1e0 + 0x14c) = *(uint *)(local_1e0 + 0x14c) & 0xf000;
        *(uint *)(local_1e0 + 0x14c) = *(uint *)(local_1e0 + 0x14c) | 1;
      }
      else {
        bVar8 = true;
        *(undefined2 *)(plVar19 + 2) = 6;
      }
    }
    FUN_0010a511(plVar19,0,0);
    *(int *)((long)plVar19 + 0x84) = *(int *)((long)unaff_R12 + 0x34) + -1;
LAB_0010c36c:
    if ((3 < *(short *)((long)plVar19 + 0x1e)) &&
       (*(uint *)(plVar19 + 0x16) < *(uint *)((long)plVar19 + 0xac))) {
      *(undefined4 *)((long)plVar19 + 0xac) = *(undefined4 *)(plVar19 + 0x16);
    }
    *(undefined2 *)((long)plVar19 + 0x1e) = 0;
    if (*(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0x15) < 1) {
      uVar17 = *(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0xf);
      if ((*(short *)((long)plVar19 + 0xb6) != 0) &&
         (0 < *(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0x17))) {
        FUN_0010cc41(plVar19,(int)*(short *)((long)plVar19 + 0xb6));
      }
      if (*(int *)((long)unaff_R12 + 0x38) == *(int *)(plVar19 + 0x15)) {
        *(undefined2 *)((long)plVar19 + 0x12) = 0;
        bVar8 = true;
      }
      else if (*(short *)((long)plVar19 + 0x14) == 0) {
        *(undefined2 *)((long)plVar19 + 0x12) = *(undefined2 *)((long)plVar19 + 0x1c);
      }
      uVar3 = *(uint *)((long)plVar19 + 0xac);
      uVar21 = (uint)*(ushort *)(plVar19 + 4);
      if (*(uint *)(plVar19 + 0x16) < uVar3) {
        uVar21 = (uVar21 * uVar21) / uVar3;
      }
      uVar18 = 0xffff << (*(byte *)((long)plVar19 + 0xcc) & 0x1f);
      uVar13 = uVar3 + uVar21;
      if (uVar18 <= uVar3 + uVar21) {
        uVar13 = uVar18;
      }
      *(uint *)((long)plVar19 + 0xac) = uVar13;
      bVar22 = uVar17 <= *(uint *)(local_1e0 + 0x188);
      if (bVar22) {
        FUN_00116250(local_1e0,uVar17);
        *(uint *)(plVar19 + 0x12) = *(int *)(plVar19 + 0x12) - uVar17;
      }
      else {
        *(int *)(plVar19 + 0x12) = *(int *)(plVar19 + 0x12) - *(int *)(local_1e0 + 0x188);
        FUN_00116250(local_1e0,*(undefined4 *)(local_1e0 + 0x188));
      }
      bVar22 = !bVar22;
      *(undefined4 *)(plVar19 + 0xf) = *(undefined4 *)((long)unaff_R12 + 0x38);
      if (*(int *)((long)plVar19 + 0x7c) - *(int *)(plVar19 + 0xf) < 0) {
        *(undefined4 *)((long)plVar19 + 0x7c) = *(undefined4 *)(plVar19 + 0xf);
      }
      sVar2 = *(short *)(plVar19 + 2);
      if (sVar2 != 10) {
        if (sVar2 < 0xb) {
          if (sVar2 == 8) {
            if (bVar22) {
              FUN_0010e72f(plVar19);
              goto LAB_0010caa5;
            }
          }
          else if (sVar2 < 9) {
            if (sVar2 == 6) {
              if (bVar22) {
                if ((*(uint *)(local_1e0 + 0x14c) & 8) != 0) {
                  *(undefined2 *)(plVar19 + 3) = 0x4b0;
                }
                *(undefined2 *)(plVar19 + 2) = 9;
              }
            }
            else if ((sVar2 == 7) && (bVar22)) {
              *(undefined2 *)(plVar19 + 2) = 10;
              FUN_001130cf(plVar19);
              *(undefined2 *)(plVar19 + 3) = 0x14;
            }
          }
        }
        goto LAB_0010c5c4;
      }
      *(undefined2 *)(plVar19 + 3) = 0x14;
    }
LAB_0010c99c:
    if ((bVar20 & 4) == 0) {
      FUN_00110e00(param_1);
      *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
      FUN_00105b44(plVar19);
      goto LAB_0010caba;
    }
    goto LAB_0010caa5;
  }
  if ((2 < iVar14) && (iVar14 - 4U < 7)) {
    if (0 < *(int *)((long)unaff_R12 + 0x38) - *(int *)(plVar19 + 0xf)) goto LAB_0010c36c;
    if ((*(short *)((long)unaff_R12 + 0x2e) == 0) && (local_208 == *(uint *)(plVar19 + 0x12))) {
      if ((DAT_001231c0 & 2) != 0) {
        g_log("Slirp",0x80," dup ack  m = %p  so = %p",param_1,local_1e0);
      }
      if ((*(short *)((long)plVar19 + 0x12) != 0) &&
         (*(int *)((long)unaff_R12 + 0x38) == *(int *)(plVar19 + 0xf))) {
        *(short *)((long)plVar19 + 0x1e) = *(short *)((long)plVar19 + 0x1e) + 1;
        if (*(short *)((long)plVar19 + 0x1e) == 3) {
          iVar14 = *(int *)((long)plVar19 + 0x7c);
          uVar17 = *(uint *)(plVar19 + 0x12);
          if (*(uint *)((long)plVar19 + 0xac) <= *(uint *)(plVar19 + 0x12)) {
            uVar17 = *(uint *)((long)plVar19 + 0xac);
          }
          uVar1 = *(ushort *)(plVar19 + 4);
          local_200 = (uVar17 >> 1) / (uint)uVar1;
          if (local_200 < 2) {
            local_200 = 2;
          }
          *(uint *)(plVar19 + 0x16) = *(ushort *)(plVar19 + 4) * local_200;
          *(undefined2 *)((long)plVar19 + 0x12) = 0;
          *(undefined2 *)((long)plVar19 + 0xb6) = 0;
          *(undefined4 *)((long)plVar19 + 0x7c) = *(undefined4 *)((long)unaff_R12 + 0x38);
          *(uint *)((long)plVar19 + 0xac) = (uint)*(ushort *)(plVar19 + 4);
          FUN_00105b44(plVar19,(ulong)uVar1,(ulong)(uVar17 >> 1) % (ulong)uVar1);
          *(uint *)((long)plVar19 + 0xac) =
               *(int *)(plVar19 + 0x16) +
               (int)*(short *)((long)plVar19 + 0x1e) * (uint)*(ushort *)(plVar19 + 4);
          if (0 < iVar14 - *(int *)((long)plVar19 + 0x7c)) {
            *(int *)((long)plVar19 + 0x7c) = iVar14;
          }
        }
        else {
          if (*(short *)((long)plVar19 + 0x1e) < 4) goto LAB_0010c5c4;
          *(uint *)((long)plVar19 + 0xac) =
               (uint)*(ushort *)(plVar19 + 4) + *(int *)((long)plVar19 + 0xac);
          FUN_00105b44(plVar19);
        }
        goto LAB_0010caa5;
      }
      *(undefined2 *)((long)plVar19 + 0x1e) = 0;
    }
    else {
      *(undefined2 *)((long)plVar19 + 0x1e) = 0;
    }
  }
LAB_0010c5c4:
  if (((bVar20 & 0x10) != 0) &&
     ((*(int *)((long)plVar19 + 0x84) - *(int *)((long)unaff_R12 + 0x34) < 0 ||
      ((*(int *)((long)plVar19 + 0x84) == *(int *)((long)unaff_R12 + 0x34) &&
       ((*(int *)(plVar19 + 0x11) - *(int *)((long)unaff_R12 + 0x38) < 0 ||
        ((*(int *)(plVar19 + 0x11) == *(int *)((long)unaff_R12 + 0x38) &&
         (*(uint *)(plVar19 + 0x12) < local_208)))))))))) {
    *(uint *)(plVar19 + 0x12) = local_208;
    *(undefined4 *)((long)plVar19 + 0x84) = *(undefined4 *)((long)unaff_R12 + 0x34);
    *(undefined4 *)(plVar19 + 0x11) = *(undefined4 *)((long)unaff_R12 + 0x38);
    if (*(uint *)((long)plVar19 + 0xc4) < *(uint *)(plVar19 + 0x12)) {
      *(undefined4 *)((long)plVar19 + 0xc4) = *(undefined4 *)(plVar19 + 0x12);
    }
    bVar8 = true;
  }
  if ((((bVar20 & 0x20) == 0) || (*(short *)((long)unaff_R12 + 0x42) == 0)) ||
     (9 < *(short *)(plVar19 + 2))) {
    if (0 < *(int *)(plVar19 + 0x13) - *(int *)((long)plVar19 + 0x9c)) {
      *(undefined4 *)((long)plVar19 + 0x9c) = *(undefined4 *)(plVar19 + 0x13);
    }
  }
  else if (*(uint *)(local_1e0 + 0x16c) <
           (uint)*(ushort *)((long)unaff_R12 + 0x42) + *(int *)(local_1e0 + 0x168)) {
    *(undefined2 *)((long)unaff_R12 + 0x42) = 0;
    bVar20 = bVar20 & 0xdf;
  }
  else if (0 < (int)((*(int *)((long)unaff_R12 + 0x34) + (uint)*(ushort *)((long)unaff_R12 + 0x42))
                    - *(int *)((long)plVar19 + 0x9c))) {
    *(uint *)((long)plVar19 + 0x9c) =
         (uint)*(ushort *)((long)unaff_R12 + 0x42) + *(int *)((long)unaff_R12 + 0x34);
    *(int *)(local_1e0 + 0x40) =
         (*(int *)((long)plVar19 + 0x9c) - *(int *)(plVar19 + 0x13)) + *(int *)(local_1e0 + 0x168);
    *(uint *)((long)plVar19 + 0x9c) =
         (uint)*(ushort *)((long)unaff_R12 + 0x42) + *(int *)((long)unaff_R12 + 0x34);
  }
  if (((*(short *)((long)unaff_R12 + 0x2e) != 0) && (*(ushort *)((long)unaff_R12 + 0x2e) < 6)) &&
     (*(char *)((long)unaff_R12 + 0x44) == '\x1b')) {
    *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
  }
  if (((*(short *)((long)unaff_R12 + 0x2e) == 0) && ((bVar20 & 1) == 0)) ||
     (9 < *(short *)(plVar19 + 2))) {
    FUN_00110e00(local_230);
    bVar10 = 0;
  }
  else if (((*(int *)((long)unaff_R12 + 0x34) == *(int *)(plVar19 + 0x13)) &&
           (plVar19 == (long *)*plVar19)) && (*(short *)(plVar19 + 2) == 4)) {
    *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 2;
    *(uint *)(plVar19 + 0x13) = (uint)*(ushort *)((long)unaff_R12 + 0x2e) + *(int *)(plVar19 + 0x13)
    ;
    bVar10 = *(byte *)((long)unaff_R12 + 0x3d) & 1;
    if (*(char *)(local_1e0 + 0x149) == '\0') {
      FUN_0010872a(local_1e0,local_230);
    }
    else {
      iVar14 = FUN_0010f408(local_1e0,local_230);
      if (iVar14 != 0) {
        FUN_0010872a(local_1e0,local_230);
      }
    }
  }
  else {
    bVar10 = FUN_0010a511(plVar19,unaff_R12,local_230);
    *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
  }
  if ((bVar10 & 1) != 0) {
    if (*(short *)(plVar19 + 2) < 10) {
      FUN_00115d35(local_1e0);
      *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
      *(int *)(plVar19 + 0x13) = *(int *)(plVar19 + 0x13) + 1;
    }
    sVar2 = *(short *)(plVar19 + 2);
    if (sVar2 == 10) {
      *(undefined2 *)(plVar19 + 3) = 0x14;
    }
    else if (sVar2 < 0xb) {
      if (sVar2 == 9) {
        *(undefined2 *)(plVar19 + 2) = 10;
        FUN_001130cf(plVar19);
        *(undefined2 *)(plVar19 + 3) = 0x14;
      }
      else if (sVar2 < 10) {
        if (sVar2 < 5) {
          if (2 < sVar2) {
            if (*(char *)(local_1e0 + 0x149) == '\x01') {
              *(undefined2 *)(plVar19 + 2) = 8;
            }
            else {
              *(undefined2 *)(plVar19 + 2) = 5;
            }
          }
        }
        else if (sVar2 == 6) {
          *(undefined2 *)(plVar19 + 2) = 7;
        }
      }
    }
  }
  if ((bVar8) || ((*(ushort *)((long)plVar19 + 0x24) & 1) != 0)) {
    FUN_00105b44(plVar19);
  }
LAB_0010caba:
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
LAB_0010b6bb:
  if (local_1d8 == 0) goto LAB_0010b6c5;
  if ((*(uint *)(local_1d8 + 0x14) == (uint)*(ushort *)(local_1e0 + 0x4a)) &&
     (*(int *)(local_1e0 + 0x4c) == *(int *)(local_1d8 + 0x10))) {
    *(uint *)(local_1e0 + 0x14c) = *(uint *)(local_1e0 + 0x14c) | 0x80;
    goto LAB_0010b6c5;
  }
  local_1d8 = *(long *)(local_1d8 + 0x28);
  goto LAB_0010b6bb;
LAB_0010b6c5:
  if ((*(uint *)(local_1e0 + 0x14c) & 0x80) == 0) {
LAB_0010b6df:
    if ((*(byte *)(local_1e0 + 0x149) & 0x10) == 0) {
      iVar14 = FUN_0010e996(local_1e0,*(undefined2 *)(local_1e0 + 0x48));
      if ((((iVar14 == -1) && (piVar15 = __errno_location(), *piVar15 != 0xb)) &&
          (piVar15 = __errno_location(), *piVar15 != 0x73)) &&
         (piVar15 = __errno_location(), *piVar15 != 0xb)) {
        if ((DAT_001231c0 & 2) != 0) {
          piVar15 = __errno_location();
          pcVar16 = strerror(*piVar15);
          piVar15 = __errno_location();
          g_log("Slirp",0x80," tcp fconnect errno = %d-%s",*piVar15,pcVar16);
        }
        piVar15 = __errno_location();
        if (*piVar15 == 0x6f) {
          FUN_0010dde3(plVar19,unaff_R12,param_1,*(int *)((long)unaff_R12 + 0x34) + 1,0,0x14,param_4
                      );
        }
        else {
          if (param_4 == 2) {
            local_221 = 0;
            piVar15 = __errno_location();
            if (*piVar15 == 0x71) {
              local_221 = 1;
            }
          }
          else if (param_4 == 10) {
            local_221 = 0;
            piVar15 = __errno_location();
            if (*piVar15 == 0x71) {
              local_221 = 3;
            }
          }
          else {
            g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_input.c"
                       ,0x290,"tcp_input",0);
          }
          uVar12 = htonl(*(uint32_t *)((long)unaff_R12 + 0x34));
          *(uint32_t *)((long)unaff_R12 + 0x34) = uVar12;
          uVar12 = htonl(*(uint32_t *)((long)unaff_R12 + 0x38));
          *(uint32_t *)((long)unaff_R12 + 0x38) = uVar12;
          uVar11 = htons(*(uint16_t *)((long)unaff_R12 + 0x3e));
          *(uint16_t *)((long)unaff_R12 + 0x3e) = uVar11;
          uVar11 = htons(*(uint16_t *)((long)unaff_R12 + 0x42));
          *(uint16_t *)((long)unaff_R12 + 0x42) = uVar11;
          *(long *)(param_1 + 0x30) = (-0x30 - (long)(int)uVar17) + *(long *)(param_1 + 0x30);
          *(uint *)(param_1 + 0x38) = uVar17 + *(int *)(param_1 + 0x38) + 0x30;
          if (param_4 == 2) {
            *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 0x1c;
            *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -0x1c;
            *puVar4 = local_198;
            puVar4[1] = local_190;
            *(undefined4 *)(puVar4 + 2) = local_188;
            piVar15 = __errno_location();
            pcVar16 = strerror(*piVar15);
            FUN_00117ef4(param_1,3,local_221,0,pcVar16);
          }
          else if (param_4 == 10) {
            *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 8;
            *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -8;
            *puVar5 = local_178;
            puVar5[1] = local_170;
            puVar5[2] = local_168;
            puVar5[3] = local_160;
            puVar5[4] = local_158;
            FUN_00111956(param_1,1,local_221);
          }
          else {
            g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_input.c"
                       ,0x2ac,"tcp_input",0);
          }
        }
        FUN_0010e72f(plVar19);
        FUN_00110e00(param_1);
      }
      else {
        *(long *)(local_1e0 + 0x30) = param_1;
        *(void **)(local_1e0 + 0x38) = unaff_R12;
        *(undefined2 *)((long)plVar19 + 0x16) = 0x96;
        *(undefined2 *)(plVar19 + 2) = 3;
        *(undefined4 *)(plVar19 + 0x14) = *(undefined4 *)((long)unaff_R12 + 0x34);
        *(int *)(plVar19 + 0x13) = *(int *)(plVar19 + 0x14) + 1;
        *(undefined4 *)((long)plVar19 + 0xa4) = *(undefined4 *)(plVar19 + 0x13);
        FUN_0010dc73(plVar19);
      }
      goto LAB_0010caba;
    }
    *(byte *)(local_1e0 + 0x149) = *(byte *)(local_1e0 + 0x149) & 0xef;
  }
LAB_0010bb05:
  FUN_0010dc73(plVar19);
  if (local_1e8 != 0) {
    FUN_0010cadd(plVar19,local_1e8,local_220,unaff_R12);
  }
  if (local_20c == 0) {
    *(undefined4 *)((long)plVar19 + 0x8c) = *(undefined4 *)(local_1d0 + 0x370);
  }
  else {
    *(int *)((long)plVar19 + 0x8c) = local_20c;
  }
  *(int *)(local_1d0 + 0x370) = *(int *)(local_1d0 + 0x370) + 64000;
  *(undefined4 *)(plVar19 + 0x14) = *(undefined4 *)((long)unaff_R12 + 0x34);
  *(undefined4 *)(plVar19 + 0x10) = *(undefined4 *)((long)plVar19 + 0x8c);
  *(undefined4 *)(plVar19 + 0x15) = *(undefined4 *)(plVar19 + 0x10);
  *(undefined4 *)((long)plVar19 + 0x7c) = *(undefined4 *)(plVar19 + 0x15);
  *(undefined4 *)(plVar19 + 0xf) = *(undefined4 *)((long)plVar19 + 0x7c);
  *(int *)(plVar19 + 0x13) = *(int *)(plVar19 + 0x14) + 1;
  *(undefined4 *)((long)plVar19 + 0xa4) = *(undefined4 *)(plVar19 + 0x13);
  *(ushort *)((long)plVar19 + 0x24) = *(ushort *)((long)plVar19 + 0x24) | 1;
  *(undefined2 *)(plVar19 + 2) = 3;
  *(undefined2 *)((long)plVar19 + 0x16) = 0x96;
LAB_0010bd1a:
  *(int *)((long)unaff_R12 + 0x34) = *(int *)((long)unaff_R12 + 0x34) + 1;
  if (*(uint *)((long)plVar19 + 0x94) < (uint)*(ushort *)((long)unaff_R12 + 0x2e)) {
    FUN_00111173(local_230,
                 -((uint)*(ushort *)((long)unaff_R12 + 0x2e) - *(int *)((long)plVar19 + 0x94)));
    *(short *)((long)unaff_R12 + 0x2e) = (short)*(undefined4 *)((long)plVar19 + 0x94);
    bVar20 = bVar20 & 0xfe;
  }
  *(int *)((long)plVar19 + 0x84) = *(int *)((long)unaff_R12 + 0x34) + -1;
  *(undefined4 *)((long)plVar19 + 0x9c) = *(undefined4 *)((long)unaff_R12 + 0x34);
  goto LAB_0010c5c4;
}



void FUN_0010cadd(undefined8 param_1,char *param_2,int param_3,long param_4)

{
  char cVar1;
  long lVar2;
  uint16_t uVar3;
  long in_FS_OFFSET;
  int local_3c;
  char *local_38;
  uint local_18;
  
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_dooptions...");
  }
  local_3c = param_3;
  local_38 = param_2;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p  cnt=%i",param_1,param_3);
  }
  for (; (0 < local_3c && (cVar1 = *local_38, cVar1 != '\0')); local_38 = local_38 + (int)local_18)
  {
    if (cVar1 == '\x01') {
      local_18 = 1;
    }
    else {
      local_18 = (uint)(byte)local_38[1];
      if (local_18 == 0) break;
    }
    if (((cVar1 == '\x02') && (local_18 == 4)) && ((*(byte *)(param_4 + 0x3d) & 2) != 0)) {
      uVar3 = ntohs(*(uint16_t *)(local_38 + 2));
      FUN_0010ce01(param_1,uVar3);
    }
    local_3c = local_3c - local_18;
  }
  if (lVar2 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0010cc41(long param_1,int param_2)

{
  short sVar1;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_xmit_timer...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," rtt = %d",param_2);
  }
  if (*(short *)(param_1 + 0xbc) == 0) {
    *(short *)(param_1 + 0xbc) = (short)(param_2 << 3);
    *(short *)(param_1 + 0xbe) = (short)param_2 * 2;
  }
  else {
    sVar1 = ((short)param_2 - (*(short *)(param_1 + 0xbc) >> 3)) + -1;
    *(short *)(param_1 + 0xbc) = sVar1 + *(short *)(param_1 + 0xbc);
    if (*(short *)(param_1 + 0xbc) < 1) {
      *(undefined2 *)(param_1 + 0xbc) = 1;
    }
    if (sVar1 < 0) {
      sVar1 = -sVar1;
    }
    *(short *)(param_1 + 0xbe) =
         (sVar1 - (*(short *)(param_1 + 0xbe) >> 2)) + *(short *)(param_1 + 0xbe);
    if (*(short *)(param_1 + 0xbe) < 1) {
      *(undefined2 *)(param_1 + 0xbe) = 1;
    }
  }
  *(undefined2 *)(param_1 + 0xb6) = 0;
  *(undefined2 *)(param_1 + 0x1a) = 0;
  *(short *)(param_1 + 0x1c) = *(short *)(param_1 + 0xbe) + (*(short *)(param_1 + 0xbc) >> 3);
  if (*(short *)(param_1 + 0x1c) < *(short *)(param_1 + 0xc0)) {
    *(undefined2 *)(param_1 + 0x1c) = *(undefined2 *)(param_1 + 0xc0);
  }
  else if (0x18 < *(short *)(param_1 + 0x1c)) {
    *(undefined2 *)(param_1 + 0x1c) = 0x18;
  }
  *(undefined2 *)(param_1 + 0xca) = 0;
  return;
}



uint FUN_0010ce01(long param_1,uint param_2)

{
  int iVar1;
  long lVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  uint local_14;
  
  lVar2 = *(long *)(param_1 + 0x70);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_mss...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," offer = %d",param_2);
  }
  if (*(short *)(lVar2 + 0x48) == 2) {
    iVar1 = *(int *)(*(long *)(lVar2 + 0x28) + 0x8c);
    iVar3 = *(int *)(*(long *)(lVar2 + 0x28) + 0x88);
    if (iVar1 <= iVar3) {
      iVar3 = iVar1;
    }
    local_14 = iVar3 - 0x28;
  }
  else if (*(short *)(lVar2 + 0x48) == 10) {
    iVar1 = *(int *)(*(long *)(lVar2 + 0x28) + 0x8c);
    iVar3 = *(int *)(*(long *)(lVar2 + 0x28) + 0x88);
    if (iVar1 <= iVar3) {
      iVar3 = iVar1;
    }
    local_14 = iVar3 - 0x3c;
  }
  else {
    g_assertion_message_expr
              ("Slirp",
               "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_input.c"
               ,0x5ee,"tcp_mss",0);
  }
  if ((param_2 != 0) && (param_2 <= local_14)) {
    local_14 = param_2;
  }
  uVar4 = 0x20;
  if (0x1f < (int)local_14) {
    uVar4 = local_14;
  }
  if (((int)uVar4 < (int)(uint)*(ushort *)(param_1 + 0x20)) || (param_2 != 0)) {
    uVar5 = 0x8000;
    if ((int)uVar4 < 0x8001) {
      uVar5 = uVar4;
    }
    *(short *)(param_1 + 0x20) = (short)uVar5;
  }
  *(uint *)(param_1 + 0xac) = uVar4;
  if ((int)(0x20000 % (long)(int)uVar4) == 0) {
    lVar6 = 0x20000;
  }
  else {
    lVar6 = (long)(int)((uVar4 - (int)(0x20000 % (long)(int)uVar4)) + 0x20000);
  }
  FUN_001086bd(lVar2 + 0x188,lVar6);
  if ((int)(0x20000 % (long)(int)uVar4) == 0) {
    lVar6 = 0x20000;
  }
  else {
    lVar6 = (long)(int)((uVar4 - (int)(0x20000 % (long)(int)uVar4)) + 0x20000);
  }
  FUN_001086bd(lVar2 + 0x168,lVar6);
  if ((DAT_001231c0 & 2) != 0) {
    g_log("Slirp",0x80," returning mss = %d",uVar4);
  }
  return uVar4;
}



void FUN_0010d04e(long param_1)

{
  *(long *)(param_1 + 0x18) = param_1;
  *(undefined8 *)(param_1 + 0x10) = *(undefined8 *)(param_1 + 0x18);
  return;
}



void FUN_0010d075(long param_1,long param_2)

{
  *(undefined8 *)(param_1 + 0x10) = *(undefined8 *)(param_2 + 0x10);
  *(long *)(param_2 + 0x10) = param_1;
  *(long *)(param_1 + 0x18) = param_2;
  *(long *)(*(long *)(param_1 + 0x10) + 0x18) = param_1;
  return;
}



void FUN_0010d0c0(long param_1)

{
  *(undefined8 *)(*(long *)(param_1 + 0x18) + 0x10) = *(undefined8 *)(param_1 + 0x10);
  *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x18) = *(undefined8 *)(param_1 + 0x18);
  return;
}



void FUN_0010d0f7(long param_1)

{
  *(long *)(param_1 + 200) = param_1 + 0xc0;
  *(undefined8 *)(param_1 + 0xc0) = *(undefined8 *)(param_1 + 200);
  *(long *)(param_1 + 0xd8) = param_1 + 0xd0;
  *(undefined8 *)(param_1 + 0xd0) = *(undefined8 *)(param_1 + 0xd8);
  return;
}



void FUN_0010d15e(long param_1,long param_2)

{
  long lVar1;
  long local_18;
  
  lVar1 = *(long *)(param_2 + 0x40);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"if_output...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," ifm = %p",param_2);
  }
  if ((*(uint *)(param_2 + 0x20) & 4) != 0) {
    FUN_00106a6a(param_2);
    *(uint *)(param_2 + 0x20) = *(uint *)(param_2 + 0x20) & 0xfffffffb;
  }
  if (param_1 != 0) {
    for (local_18 = *(long *)(lVar1 + 0xd8); local_18 != lVar1 + 0xd0;
        local_18 = *(long *)(local_18 + 8)) {
      if (param_1 == *(long *)(local_18 + 0x28)) {
        *(long *)(param_2 + 0x28) = param_1;
        FUN_0010d075(param_2,*(undefined8 *)(local_18 + 0x18));
        goto LAB_0010d347;
      }
    }
  }
  if ((param_1 == 0) || ((*(byte *)(param_1 + 0x148) & 0x10) == 0)) {
    local_18 = *(long *)(lVar1 + 0xd8);
  }
  else {
    local_18 = *(long *)(lVar1 + 200);
    if (param_1 == *(long *)(local_18 + 0x28)) {
      *(long *)(param_2 + 0x28) = param_1;
      FUN_0010d075(param_2,*(undefined8 *)(local_18 + 0x18));
      goto LAB_0010d347;
    }
  }
  *(long *)(param_2 + 0x28) = param_1;
  FUN_0010d04e(param_2);
  FUN_00106a33(param_2,local_18);
LAB_0010d347:
  if (param_1 != 0) {
    *(int *)(param_1 + 0x15c) = *(int *)(param_1 + 0x15c) + 1;
    *(int *)(param_1 + 0x160) = *(int *)(param_1 + 0x160) + 1;
    if (((true) && (5 < *(int *)(param_1 + 0x160))) &&
       (2 < *(int *)(param_1 + 0x160) - *(int *)(param_1 + 0x15c))) {
      FUN_00106a6a(*(undefined8 *)(param_2 + 0x10));
      FUN_00106a33(*(undefined8 *)(param_2 + 0x10),lVar1 + 0xd0);
    }
  }
  FUN_0010d3f3(*(undefined8 *)(param_2 + 0x40));
  return;
}



void FUN_0010d3f3(long param_1)

{
  long lVar1;
  long *plVar2;
  bool bVar3;
  long *plVar4;
  int iVar5;
  ulong uVar6;
  long *local_38;
  long *local_30;
  
  uVar6 = (**(code **)(*(long *)(param_1 + 0x1768) + 0x10))(*(undefined8 *)(param_1 + 6000));
  bVar3 = false;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"if_start...");
  }
  if (*(char *)(param_1 + 0xe0) == '\0') {
    *(undefined *)(param_1 + 0xe0) = 1;
    local_30 = (long *)0x0;
    if (*(long *)(param_1 + 0xd0) != param_1 + 0xd0) {
      local_30 = *(long **)(param_1 + 0xd0);
    }
    if (*(long *)(param_1 + 0xc0) == param_1 + 0xc0) {
      if (local_30 == (long *)0x0) {
        local_38 = (long *)0x0;
      }
      else {
        local_38 = local_30;
        bVar3 = true;
      }
    }
    else {
      local_38 = *(long **)(param_1 + 0xc0);
    }
    while (plVar4 = local_38, local_38 != (long *)0x0) {
      local_38 = (long *)*local_38;
      if (local_38 == (long *)(param_1 + 0xc0)) {
        local_38 = local_30;
        bVar3 = true;
      }
      if (local_38 == (long *)(param_1 + 0xd0)) {
        local_38 = (long *)0x0;
      }
      if (((ulong)plVar4[10] < uVar6) || (iVar5 = FUN_00104c4c(param_1,plVar4), iVar5 != 0)) {
        lVar1 = plVar4[1];
        FUN_00106a6a(plVar4);
        if (plVar4 != (long *)plVar4[2]) {
          plVar2 = (long *)plVar4[2];
          FUN_00106a33(plVar2,lVar1);
          FUN_0010d0c0(plVar4);
          if (!bVar3) {
            local_38 = plVar2;
          }
        }
        if (plVar4[5] != 0) {
          lVar1 = plVar4[5];
          *(int *)(lVar1 + 0x15c) = *(int *)(lVar1 + 0x15c) + -1;
          if (*(int *)(lVar1 + 0x15c) == 0) {
            *(undefined4 *)(plVar4[5] + 0x160) = 0;
          }
        }
        FUN_00110e00(plVar4);
      }
    }
    *(undefined *)(param_1 + 0xe0) = 0;
  }
  return;
}



uint FUN_0010d634(long param_1,int param_2)

{
  long lVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  ushort *puVar5;
  int iVar6;
  long in_FS_OFFSET;
  int local_54;
  undefined2 local_36;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  uVar4 = 0;
  iVar6 = 0;
  bVar2 = false;
  local_54 = param_2;
  if (*(int *)(param_1 + 0x38) != 0) {
    puVar5 = *(ushort **)(param_1 + 0x30);
    iVar6 = *(int *)(param_1 + 0x38);
    if (param_2 < *(int *)(param_1 + 0x38)) {
      iVar6 = param_2;
    }
    local_54 = param_2 - iVar6;
    if ((((ulong)puVar5 & 1) != 0) && (0 < iVar6)) {
      iVar3 = 0;
      if (false) {
        iVar3 = -0xffff;
      }
      uVar4 = iVar3 << 8;
      local_36 = (ushort)*(byte *)puVar5;
      puVar5 = (ushort *)((long)puVar5 + 1);
      bVar2 = true;
      iVar6 = iVar6 + -1;
    }
    while (-1 < iVar6 + -0x20) {
      uVar4 = uVar4 + *puVar5 + (uint)puVar5[1] + (uint)puVar5[2] + (uint)puVar5[3] +
              (uint)puVar5[4] + (uint)puVar5[5] + (uint)puVar5[6] + (uint)puVar5[7] +
              (uint)puVar5[8] + (uint)puVar5[9] + (uint)puVar5[10] + (uint)puVar5[0xb] +
              (uint)puVar5[0xc] + (uint)puVar5[0xd] + (uint)puVar5[0xe] + (uint)puVar5[0xf];
      puVar5 = puVar5 + 0x10;
      iVar6 = iVar6 + -0x20;
    }
    while (-1 < iVar6 + -8) {
      uVar4 = uVar4 + *puVar5 + (uint)puVar5[1] + (uint)puVar5[2] + (uint)puVar5[3];
      puVar5 = puVar5 + 4;
      iVar6 = iVar6 + -8;
    }
    if ((iVar6 != 0) || (bVar2)) {
      uVar4 = (uVar4 & 0xffff) + (uVar4 >> 0x10);
      if (0xffff < uVar4) {
        uVar4 = uVar4 - 0xffff;
      }
      while (iVar6 = iVar6 + -2, -1 < iVar6) {
        uVar4 = uVar4 + *puVar5;
        puVar5 = puVar5 + 1;
      }
      if (bVar2) {
        uVar4 = (uVar4 & 0xffff) + (uVar4 >> 0x10);
        if (0xffff < uVar4) {
          uVar4 = uVar4 - 0xffff;
        }
        uVar4 = uVar4 * 0x100;
        if (iVar6 == -1) {
          local_36 = CONCAT11(*(byte *)puVar5,(undefined)local_36);
          uVar4 = uVar4 + local_36;
          iVar6 = 0;
        }
        else {
          iVar6 = -1;
        }
      }
      else if (iVar6 == -1) {
        local_36 = (ushort)*(byte *)puVar5;
      }
    }
    else {
      iVar6 = 0;
    }
  }
  if (local_54 != 0) {
    if ((DAT_001231c0 & 4) != 0) {
      g_log("Slirp",0x80,"cksum: out of data");
    }
    if ((DAT_001231c0 & 4) != 0) {
      g_log("Slirp",0x80," len = %d",local_54);
    }
  }
  if (iVar6 == -1) {
    local_36 = local_36 & 0xff;
    uVar4 = uVar4 + local_36;
  }
  uVar4 = (uVar4 & 0xffff) + (uVar4 >> 0x10);
  if (0xffff < uVar4) {
    uVar4 = uVar4 - 0xffff;
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return ~uVar4 & 0xffff;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined4 FUN_0010d98f(long param_1)

{
  long lVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  uint16_t uVar9;
  uint32_t uVar10;
  undefined4 uVar11;
  long in_FS_OFFSET;
  uint16_t uStack_44;
  undefined uStack_42;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puVar2 = *(undefined8 **)(param_1 + 0x30);
  puVar3 = *(undefined8 **)(param_1 + 0x30);
  uVar4 = *puVar2;
  uVar5 = puVar2[1];
  uVar6 = puVar2[2];
  uVar7 = puVar2[3];
  uVar8 = puVar2[4];
  *puVar3 = uVar5;
  puVar3[1] = uVar6;
  puVar3[2] = uVar7;
  puVar3[3] = uVar8;
  uStack_44 = (uint16_t)((ulong)uVar4 >> 0x20);
  uVar9 = ntohs(uStack_44);
  uVar10 = htonl((uint)uVar9);
  *(uint32_t *)(puVar3 + 4) = uVar10;
  *(undefined2 *)((long)puVar3 + 0x24) = 0;
  *(undefined *)((long)puVar3 + 0x26) = 0;
  uStack_42 = (undefined)((ulong)uVar4 >> 0x30);
  *(undefined *)((long)puVar3 + 0x27) = uStack_42;
  uVar10 = ntohl(*(uint32_t *)(puVar3 + 4));
  uVar11 = FUN_0010d634(param_1,uVar10 + 0x28);
  *puVar2 = uVar4;
  puVar2[1] = uVar5;
  puVar2[2] = uVar6;
  puVar2[3] = uVar7;
  puVar2[4] = uVar8;
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar11;
}



void FUN_0010dac2(int param_1)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 1;
  setsockopt(param_1,6,1,&local_14,4);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_0010db1a(int param_1)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 1;
  setsockopt(param_1,1,2,&local_14,4);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



undefined8 FUN_0010db72(short *param_1)

{
  undefined8 uVar1;
  
  if (*param_1 == 2) {
    uVar1 = 0x10;
  }
  else if (*param_1 == 10) {
    uVar1 = 0x1c;
  }
  else {
    uVar1 = g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.h"
                       ,0x88,"sockaddr_size",0);
  }
  return uVar1;
}



void FUN_0010dbc9(long param_1)

{
  *(undefined4 *)(param_1 + 0x370) = 1;
  *(long *)(param_1 + 0x1c8) = param_1 + 0x1c0;
  *(undefined8 *)(param_1 + 0x1c0) = *(undefined8 *)(param_1 + 0x1c8);
  *(long *)(param_1 + 0x368) = param_1 + 0x1c0;
  return;
}



void FUN_0010dc28(long param_1)

{
  while (*(long *)(param_1 + 0x1c0) != param_1 + 0x1c0) {
    FUN_0010e72f(*(undefined8 *)(*(long *)(param_1 + 0x1c0) + 0x150));
  }
  return;
}



void FUN_0010dc73(long param_1)

{
  long lVar1;
  undefined8 uVar2;
  uint16_t uVar3;
  
  lVar1 = *(long *)(param_1 + 0x70);
  *(undefined8 *)(param_1 + 0x28) = 0;
  memset((void *)(param_1 + 0x30),0,0x24);
  *(undefined2 *)(param_1 + 0x54) = 0;
  if (*(short *)(lVar1 + 0x48) == 2) {
    *(undefined *)(param_1 + 0x39) = 6;
    uVar3 = htons(0x14);
    *(uint16_t *)(param_1 + 0x56) = uVar3;
    *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(lVar1 + 0x4c);
    *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(lVar1 + 0xcc);
    *(undefined2 *)(param_1 + 0x58) = *(undefined2 *)(lVar1 + 0x4a);
    *(undefined2 *)(param_1 + 0x5a) = *(undefined2 *)(lVar1 + 0xca);
  }
  else if (*(short *)(lVar1 + 0x48) == 10) {
    *(undefined *)(param_1 + 0x51) = 6;
    uVar3 = htons(0x14);
    *(uint16_t *)(param_1 + 0x56) = uVar3;
    uVar2 = *(undefined8 *)(lVar1 + 0x58);
    *(undefined8 *)(param_1 + 0x30) = *(undefined8 *)(lVar1 + 0x50);
    *(undefined8 *)(param_1 + 0x38) = uVar2;
    uVar2 = *(undefined8 *)(lVar1 + 0xd8);
    *(undefined8 *)(param_1 + 0x40) = *(undefined8 *)(lVar1 + 0xd0);
    *(undefined8 *)(param_1 + 0x48) = uVar2;
    *(undefined2 *)(param_1 + 0x58) = *(undefined2 *)(lVar1 + 0x4a);
    *(undefined2 *)(param_1 + 0x5a) = *(undefined2 *)(lVar1 + 0xca);
  }
  else {
    g_assertion_message_expr
              ("Slirp",
               "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_subr.c"
               ,0x60,"tcp_template",0);
  }
  *(undefined4 *)(param_1 + 0x5c) = 0;
  *(undefined4 *)(param_1 + 0x60) = 0;
  *(byte *)(param_1 + 100) = *(byte *)(param_1 + 100) & 0xf0;
  *(byte *)(param_1 + 100) = *(byte *)(param_1 + 100) & 0xf | 0x50;
  *(undefined *)(param_1 + 0x65) = 0;
  *(undefined2 *)(param_1 + 0x66) = 0;
  *(undefined2 *)(param_1 + 0x68) = 0;
  *(undefined2 *)(param_1 + 0x6a) = 0;
  return;
}



void FUN_0010dde3(long param_1,undefined8 *param_2,long param_3,uint32_t param_4,uint32_t param_5,
                 uint param_6,short param_7)

{
  undefined4 uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  long lVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  uint16_t uVar10;
  undefined2 uVar11;
  uint32_t uVar12;
  long in_FS_OFFSET;
  uint local_ac;
  long local_a0;
  undefined8 *local_98;
  int local_80;
  undefined4 local_60;
  undefined4 uStack_5c;
  undefined uStack_57;
  undefined uStack_3f;
  undefined2 uStack_3a;
  
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  local_80 = 0;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_respond...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," ti = %p",param_2);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_3);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," ack = %u",param_4);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," seq = %u",param_5);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," flags = %x",param_6);
  }
  if (param_1 != 0) {
    local_80 = *(int *)(*(long *)(param_1 + 0x70) + 0x16c) -
               *(int *)(*(long *)(param_1 + 0x70) + 0x168);
  }
  if (param_3 == 0) {
    if (param_1 == 0) goto LAB_0010e553;
    local_a0 = FUN_00110cac(*(undefined8 *)(*(long *)(param_1 + 0x70) + 0x28));
    if (local_a0 == 0) goto LAB_0010e553;
    *(long *)(local_a0 + 0x30) = *(long *)(local_a0 + 0x30) + 0x10;
    puVar3 = *(undefined8 **)(local_a0 + 0x30);
    uVar4 = param_2[1];
    *puVar3 = *param_2;
    puVar3[1] = uVar4;
    uVar4 = param_2[3];
    puVar3[2] = param_2[2];
    puVar3[3] = uVar4;
    uVar4 = param_2[5];
    puVar3[4] = param_2[4];
    puVar3[5] = uVar4;
    uVar4 = param_2[7];
    puVar3[6] = param_2[6];
    puVar3[7] = uVar4;
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_2 + 8);
    local_98 = *(undefined8 **)(local_a0 + 0x30);
    if (param_7 == 2) {
      *(undefined *)(local_98 + 2) = 0;
    }
    else if (param_7 == 10) {
      *(undefined *)(local_98 + 5) = 0;
    }
    else {
      g_assertion_message_expr
                ("Slirp",
                 "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_subr.c"
                 ,0x99,"tcp_respond",0);
    }
    local_ac = 0x10;
  }
  else {
    *(undefined8 **)(param_3 + 0x30) = param_2;
    *(undefined4 *)(param_3 + 0x38) = 0x44;
    local_ac = param_6;
    local_a0 = param_3;
    local_98 = param_2;
    if (param_7 == 2) {
      uVar1 = *(undefined4 *)((long)param_2 + 0xc);
      *(undefined4 *)((long)param_2 + 0xc) = *(undefined4 *)(param_2 + 1);
      *(undefined4 *)(param_2 + 1) = uVar1;
      uVar11 = *(undefined2 *)((long)param_2 + 0x32);
      *(undefined2 *)((long)param_2 + 0x32) = *(undefined2 *)(param_2 + 6);
      *(undefined2 *)(param_2 + 6) = uVar11;
    }
    else if (param_7 == 10) {
      uVar4 = param_2[4];
      uVar6 = param_2[3];
      param_2[3] = param_2[1];
      param_2[4] = param_2[2];
      param_2[1] = uVar6;
      param_2[2] = uVar4;
      uVar11 = *(undefined2 *)((long)param_2 + 0x32);
      *(undefined2 *)((long)param_2 + 0x32) = *(undefined2 *)(param_2 + 6);
      *(undefined2 *)(param_2 + 6) = uVar11;
    }
    else {
      g_assertion_message_expr
                ("Slirp",
                 "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_subr.c"
                 ,0xb6,"tcp_respond",0);
    }
  }
  uVar10 = htons(0x14);
  *(uint16_t *)((long)local_98 + 0x2e) = uVar10;
  *(undefined4 *)(local_a0 + 0x38) = 0x44;
  *local_98 = 0;
  *(undefined2 *)((long)local_98 + 0x2c) = 0;
  uVar12 = htonl(param_5);
  *(uint32_t *)((long)local_98 + 0x34) = uVar12;
  uVar12 = htonl(param_4);
  *(uint32_t *)(local_98 + 7) = uVar12;
  *(byte *)((long)local_98 + 0x3c) = *(byte *)((long)local_98 + 0x3c) & 0xf0;
  *(byte *)((long)local_98 + 0x3c) = *(byte *)((long)local_98 + 0x3c) & 0xf | 0x50;
  *(char *)((long)local_98 + 0x3d) = (char)local_ac;
  if (param_1 == 0) {
    uVar10 = htons((uint16_t)local_80);
    *(uint16_t *)((long)local_98 + 0x3e) = uVar10;
  }
  else {
    uVar10 = htons((uint16_t)(local_80 >> (*(byte *)(param_1 + 0xcd) & 0x1f)));
    *(uint16_t *)((long)local_98 + 0x3e) = uVar10;
  }
  *(undefined2 *)((long)local_98 + 0x42) = 0;
  *(undefined2 *)(local_98 + 8) = 0;
  uVar11 = FUN_0010d634(local_a0,0x44);
  *(undefined2 *)(local_98 + 8) = uVar11;
  lVar5 = *(long *)(local_a0 + 0x30);
  uVar4 = *(undefined8 *)(lVar5 + 8);
  uVar6 = *(undefined8 *)(lVar5 + 0x10);
  uVar7 = *(undefined8 *)(lVar5 + 0x18);
  uVar8 = *(undefined8 *)(lVar5 + 0x20);
  uVar9 = *(undefined8 *)(lVar5 + 0x28);
  if (param_7 == 2) {
    *(long *)(local_a0 + 0x30) = *(long *)(local_a0 + 0x30) + 0x1c;
    *(int *)(local_a0 + 0x38) = *(int *)(local_a0 + 0x38) + -0x1c;
    lVar5 = *(long *)(local_a0 + 0x30);
    *(short *)(lVar5 + 2) = (short)*(undefined4 *)(local_a0 + 0x38);
    uStack_5c = (undefined4)((ulong)uVar4 >> 0x20);
    *(undefined4 *)(lVar5 + 0x10) = uStack_5c;
    local_60 = (undefined4)uVar4;
    *(undefined4 *)(lVar5 + 0xc) = local_60;
    uStack_57 = (undefined)((ulong)uVar6 >> 8);
    *(undefined *)(lVar5 + 9) = uStack_57;
    if ((local_ac & 4) == 0) {
      *(undefined *)(lVar5 + 8) = 0x40;
    }
    else {
      *(undefined *)(lVar5 + 8) = 0xff;
    }
    FUN_001196c1(0,local_a0);
  }
  else if (param_7 == 10) {
    *(long *)(local_a0 + 0x30) = *(long *)(local_a0 + 0x30) + 8;
    *(int *)(local_a0 + 0x38) = *(int *)(local_a0 + 0x38) + -8;
    lVar5 = *(long *)(local_a0 + 0x30);
    uStack_3a = (undefined2)((ulong)uVar9 >> 0x30);
    *(undefined2 *)(lVar5 + 4) = uStack_3a;
    *(undefined8 *)(lVar5 + 0x18) = uVar7;
    *(undefined8 *)(lVar5 + 0x20) = uVar8;
    *(undefined8 *)(lVar5 + 8) = uVar4;
    *(undefined8 *)(lVar5 + 0x10) = uVar6;
    uStack_3f = (undefined)((ulong)uVar9 >> 8);
    *(undefined *)(lVar5 + 6) = uStack_3f;
    FUN_00107b40(0,local_a0,0);
  }
  else {
    g_assertion_message_expr
              ("Slirp",
               "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tcp_subr.c"
               ,0xf5,"tcp_respond",0);
  }
LAB_0010e553:
  if (lVar2 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



undefined8 * FUN_0010e571(long param_1)

{
  undefined2 uVar1;
  undefined8 *puVar2;
  int iVar3;
  
  puVar2 = (undefined8 *)g_malloc0_n(1,0xe0);
  puVar2[1] = puVar2;
  *puVar2 = puVar2[1];
  if (*(short *)(param_1 + 0x48) == 2) {
    iVar3 = 0x28;
  }
  else {
    iVar3 = 0x3c;
  }
  iVar3 = *(int *)(*(long *)(param_1 + 0x28) + 0x88) - iVar3;
  uVar1 = (undefined2)iVar3;
  if (0x8000 < iVar3) {
    uVar1 = 0x8000;
  }
  *(undefined2 *)(puVar2 + 4) = uVar1;
  *(undefined2 *)((long)puVar2 + 0x24) = 0;
  puVar2[0xe] = param_1;
  *(undefined2 *)((long)puVar2 + 0xbc) = 0;
  *(undefined2 *)((long)puVar2 + 0xbe) = 0x18;
  *(undefined2 *)(puVar2 + 0x18) = 2;
  *(undefined2 *)((long)puVar2 + 0x1c) = 0xc;
  if (*(short *)((long)puVar2 + 0x1c) < 2) {
    *(undefined2 *)((long)puVar2 + 0x1c) = 2;
  }
  else if (0x18 < *(short *)((long)puVar2 + 0x1c)) {
    *(undefined2 *)((long)puVar2 + 0x1c) = 0x18;
  }
  *(undefined4 *)((long)puVar2 + 0xac) = 0x3fffc000;
  *(undefined4 *)(puVar2 + 0x16) = 0x3fffc000;
  *(undefined2 *)(puVar2 + 2) = 0;
  *(undefined8 **)(param_1 + 0x150) = puVar2;
  return puVar2;
}



void FUN_0010e65c(long param_1)

{
  int *piVar1;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_drop...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    piVar1 = __errno_location();
    g_log("Slirp",0x80," errno = %d",*piVar1);
  }
  if (2 < *(short *)(param_1 + 0x10)) {
    *(undefined2 *)(param_1 + 0x10) = 0;
    FUN_00105b44(param_1);
  }
  FUN_0010e72f(param_1);
  return;
}



undefined8 FUN_0010e72f(undefined8 *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  
  lVar1 = param_1[0xe];
  lVar2 = *(long *)(lVar1 + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_close...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p",param_1);
  }
  puVar3 = (undefined8 *)*param_1;
  while (param_1 != puVar3) {
    puVar3 = (undefined8 *)*puVar3;
    uVar4 = *(undefined8 *)(puVar3[1] + 0x10);
    FUN_00106a6a(puVar3[1]);
    FUN_00110e00(uVar4);
  }
  g_free(param_1);
  *(undefined8 *)(lVar1 + 0x150) = 0;
  if (lVar1 == *(long *)(lVar2 + 0x368)) {
    *(long *)(lVar2 + 0x368) = lVar2 + 0x1c0;
  }
  (**(code **)(*(long *)(*(long *)(lVar1 + 0x28) + 0x1768) + 0x38))
            (*(undefined4 *)(lVar1 + 0x10),*(undefined8 *)(*(long *)(lVar1 + 0x28) + 6000));
  close(*(int *)(lVar1 + 0x10));
  FUN_0010858d(lVar1 + 0x168);
  FUN_0010858d(lVar1 + 0x188);
  FUN_0011385c(lVar1);
  return 0;
}



void FUN_0010e8bc(long param_1)

{
  int iVar1;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_sockclosed...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," tp = %p",param_1);
  }
  if (param_1 != 0) {
    iVar1 = (int)*(short *)(param_1 + 0x10);
    if (iVar1 == 5) {
      *(undefined2 *)(param_1 + 0x10) = 8;
    }
    else if (iVar1 < 6) {
      if (iVar1 < 3) {
        if (-1 < *(short *)(param_1 + 0x10)) {
          *(undefined2 *)(param_1 + 0x10) = 0;
          FUN_0010e72f(param_1);
          return;
        }
      }
      else if (iVar1 - 3U < 2) {
        *(undefined2 *)(param_1 + 0x10) = 6;
      }
    }
    FUN_00105b44(param_1);
  }
  return;
}



int FUN_0010e996(long param_1,undefined2 param_2)

{
  undefined4 uVar1;
  int iVar2;
  socklen_t __len;
  long in_FS_OFFSET;
  undefined4 local_b4;
  int local_b0;
  int local_ac;
  sockaddr local_a8;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_b0 = 0;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_fconnect...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  uVar1 = FUN_001081c9(param_2,1,0);
  *(undefined4 *)(param_1 + 0x10) = uVar1;
  local_b0 = *(int *)(param_1 + 0x10);
  if ((local_b0 < 0) || (local_b0 = FUN_00107a81(param_1,param_2), -1 < local_b0)) {
    iVar2 = local_b0;
    if (-1 < local_b0) {
      local_ac = *(int *)(param_1 + 0x10);
      FUN_001080a5(local_ac);
      (**(code **)(*(long *)(*(long *)(param_1 + 0x28) + 0x1768) + 0x30))
                (*(undefined4 *)(param_1 + 0x10),*(undefined8 *)(*(long *)(param_1 + 0x28) + 6000));
      FUN_0010db1a(local_ac);
      local_b4 = 1;
      setsockopt(local_ac,1,10,&local_b4,4);
      local_b4 = 1;
      setsockopt(local_ac,6,1,&local_b4,4);
      local_a8._0_8_ = *(undefined8 *)(param_1 + 0x48);
      local_a8.sa_data._6_8_ = *(undefined8 *)(param_1 + 0x50);
      local_98 = *(undefined8 *)(param_1 + 0x58);
      local_90 = *(undefined8 *)(param_1 + 0x60);
      local_88 = *(undefined8 *)(param_1 + 0x68);
      local_80 = *(undefined8 *)(param_1 + 0x70);
      local_78 = *(undefined8 *)(param_1 + 0x78);
      local_70 = *(undefined8 *)(param_1 + 0x80);
      local_68 = *(undefined8 *)(param_1 + 0x88);
      local_60 = *(undefined8 *)(param_1 + 0x90);
      local_58 = *(undefined8 *)(param_1 + 0x98);
      local_50 = *(undefined8 *)(param_1 + 0xa0);
      local_48 = *(undefined8 *)(param_1 + 0xa8);
      local_40 = *(undefined8 *)(param_1 + 0xb0);
      local_30 = *(undefined8 *)(param_1 + 0xc0);
      local_38 = *(undefined8 *)(param_1 + 0xb8);
      if ((DAT_001231c0 & 1) != 0) {
        g_log("Slirp",0x80," connect()ing...");
      }
      iVar2 = FUN_00115f9c(param_1,&local_a8);
      if (iVar2 < 0) {
        iVar2 = -1;
      }
      else {
        __len = FUN_0010db72(&local_a8);
        local_b0 = connect(local_ac,&local_a8,__len);
        FUN_00115b53(param_1);
        iVar2 = local_b0;
      }
    }
  }
  else {
    close(*(int *)(param_1 + 0x10));
    *(undefined4 *)(param_1 + 0x10) = 0xffffffff;
    iVar2 = local_b0;
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar2;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Type propagation algorithm not settling

void FUN_0010ece8(long param_1)

{
  undefined8 uVar1;
  undefined uVar2;
  long in_FS_OFFSET;
  socklen_t local_cc [3];
  long local_c0;
  long local_b8;
  long local_b0;
  sockaddr local_a8;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_b8 = *(long *)(param_1 + 0x28);
  local_cc[0] = 0x80;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_connect...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," inso = %p",param_1);
  }
  local_c0 = param_1;
  if ((*(uint *)(param_1 + 0x14c) & 0x200) == 0) {
    local_c0 = FUN_0011376d(local_b8);
    FUN_0010f24f(local_c0);
    uVar1 = *(undefined8 *)(param_1 + 0xd0);
    *(undefined8 *)(local_c0 + 200) = *(undefined8 *)(param_1 + 200);
    *(undefined8 *)(local_c0 + 0xd0) = uVar1;
    uVar1 = *(undefined8 *)(param_1 + 0xe0);
    *(undefined8 *)(local_c0 + 0xd8) = *(undefined8 *)(param_1 + 0xd8);
    *(undefined8 *)(local_c0 + 0xe0) = uVar1;
    uVar1 = *(undefined8 *)(param_1 + 0xf0);
    *(undefined8 *)(local_c0 + 0xe8) = *(undefined8 *)(param_1 + 0xe8);
    *(undefined8 *)(local_c0 + 0xf0) = uVar1;
    uVar1 = *(undefined8 *)(param_1 + 0x100);
    *(undefined8 *)(local_c0 + 0xf8) = *(undefined8 *)(param_1 + 0xf8);
    *(undefined8 *)(local_c0 + 0x100) = uVar1;
    uVar1 = *(undefined8 *)(param_1 + 0x110);
    *(undefined8 *)(local_c0 + 0x108) = *(undefined8 *)(param_1 + 0x108);
    *(undefined8 *)(local_c0 + 0x110) = uVar1;
    uVar1 = *(undefined8 *)(param_1 + 0x120);
    *(undefined8 *)(local_c0 + 0x118) = *(undefined8 *)(param_1 + 0x118);
    *(undefined8 *)(local_c0 + 0x120) = uVar1;
    uVar1 = *(undefined8 *)(param_1 + 0x130);
    *(undefined8 *)(local_c0 + 0x128) = *(undefined8 *)(param_1 + 0x128);
    *(undefined8 *)(local_c0 + 0x130) = uVar1;
    uVar1 = *(undefined8 *)(param_1 + 0x140);
    *(undefined8 *)(local_c0 + 0x138) = *(undefined8 *)(param_1 + 0x138);
    *(undefined8 *)(local_c0 + 0x140) = uVar1;
    *(undefined2 *)(local_c0 + 0x48) = *(undefined2 *)(param_1 + 0x48);
  }
  FUN_0010ce01(*(undefined8 *)(local_c0 + 0x150),0);
  local_cc[2] = accept(*(int *)(param_1 + 0x10),&local_a8,local_cc);
  if ((int)local_cc[2] < 0) {
    FUN_0010e72f(*(undefined8 *)(local_c0 + 0x150));
  }
  else {
    FUN_001080a5(local_cc[2]);
    (**(code **)(*(long *)(*(long *)(local_c0 + 0x28) + 0x1768) + 0x30))
              (*(undefined4 *)(local_c0 + 0x10),*(undefined8 *)(*(long *)(local_c0 + 0x28) + 6000));
    FUN_0010db1a(local_cc[2]);
    local_cc[1] = 1;
    setsockopt(local_cc[2],1,10,local_cc + 1,4);
    FUN_0010dac2(local_cc[2]);
    *(undefined8 *)(local_c0 + 0x48) = local_a8._0_8_;
    *(undefined8 *)(local_c0 + 0x50) = local_a8.sa_data._6_8_;
    *(undefined8 *)(local_c0 + 0x58) = local_98;
    *(undefined8 *)(local_c0 + 0x60) = local_90;
    *(undefined8 *)(local_c0 + 0x68) = local_88;
    *(undefined8 *)(local_c0 + 0x70) = local_80;
    *(undefined8 *)(local_c0 + 0x78) = local_78;
    *(undefined8 *)(local_c0 + 0x80) = local_70;
    *(undefined8 *)(local_c0 + 0x88) = local_68;
    *(undefined8 *)(local_c0 + 0x90) = local_60;
    *(undefined8 *)(local_c0 + 0x98) = local_58;
    *(undefined8 *)(local_c0 + 0xa0) = local_50;
    *(undefined8 *)(local_c0 + 0xa8) = local_48;
    *(undefined8 *)(local_c0 + 0xb0) = local_40;
    *(undefined8 *)(local_c0 + 0xb8) = local_38;
    *(undefined8 *)(local_c0 + 0xc0) = local_30;
    FUN_00116188(local_c0);
    if ((*(uint *)(param_1 + 0x14c) & 0x200) != 0) {
      (**(code **)(*(long *)(*(long *)(local_c0 + 0x28) + 0x1768) + 0x38))
                (*(undefined4 *)(local_c0 + 0x10),*(undefined8 *)(*(long *)(local_c0 + 0x28) + 6000)
                );
      close(*(int *)(local_c0 + 0x10));
      *(undefined4 *)(local_c0 + 0x14c) = 1;
    }
    *(socklen_t *)(local_c0 + 0x10) = local_cc[2];
    *(uint *)(local_c0 + 0x14c) = *(uint *)(local_c0 + 0x14c) | 0x2000;
    uVar2 = FUN_0010f297(local_c0);
    *(undefined *)(local_c0 + 0x148) = uVar2;
    local_b0 = *(long *)(local_c0 + 0x150);
    FUN_0010dc73(local_b0);
    *(undefined2 *)(local_b0 + 0x10) = 2;
    *(undefined2 *)(local_b0 + 0x16) = 0x96;
    *(undefined4 *)(local_b0 + 0x8c) = *(undefined4 *)(local_b8 + 0x370);
    *(int *)(local_b8 + 0x370) = *(int *)(local_b8 + 0x370) + 64000;
    *(undefined4 *)(local_b0 + 0x80) = *(undefined4 *)(local_b0 + 0x8c);
    *(undefined4 *)(local_b0 + 0xa8) = *(undefined4 *)(local_b0 + 0x80);
    *(undefined4 *)(local_b0 + 0x7c) = *(undefined4 *)(local_b0 + 0xa8);
    *(undefined4 *)(local_b0 + 0x78) = *(undefined4 *)(local_b0 + 0x7c);
    FUN_00105b44(local_b0);
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0010f24f(long param_1)

{
  undefined8 uVar1;
  
  uVar1 = FUN_0010e571(param_1);
  *(undefined8 *)(param_1 + 0x150) = uVar1;
  FUN_00106a33(param_1,*(long *)(param_1 + 0x28) + 0x1c0);
  return;
}



undefined FUN_0010f297(long param_1)

{
  uint16_t uVar1;
  int local_c;
  
  local_c = 0;
  while( true ) {
    if ((&DAT_0011dd24)[(long)local_c * 6] == '\0') {
      return 0;
    }
    if (((*(short *)(&DAT_0011dd22 + (long)local_c * 6) != 0) &&
        (uVar1 = ntohs(*(uint16_t *)(param_1 + 0x4a)),
        uVar1 == *(uint16_t *)(&DAT_0011dd22 + (long)local_c * 6))) ||
       ((*(short *)(&DAT_0011dd20 + (long)local_c * 6) != 0 &&
        (uVar1 = ntohs(*(uint16_t *)(param_1 + 0xca)),
        uVar1 == *(uint16_t *)(&DAT_0011dd20 + (long)local_c * 6))))) break;
    local_c = local_c + 1;
  }
  if (*(char *)(*(long *)(param_1 + 0x28) + 0x1760) != '\0') {
    *(undefined *)(param_1 + 0x149) = (&DAT_0011dd25)[(long)local_c * 6];
  }
  return (&DAT_0011dd24)[(long)local_c * 6];
}



undefined8 FUN_0010f408(long param_1,long param_2)

{
  byte bVar1;
  uint uVar2;
  uint16_t uVar3;
  uint16_t uVar4;
  int iVar5;
  undefined4 uVar6;
  uint32_t uVar7;
  byte *pbVar8;
  long lVar9;
  long in_FS_OFFSET;
  uint16_t local_182;
  uint local_180;
  uint local_17c;
  uint local_178;
  uint local_174;
  uint local_170;
  uint local_16c;
  uint32_t local_168;
  socklen_t local_164;
  int local_160;
  int local_15c;
  byte *local_158;
  undefined8 *local_150;
  long local_148;
  undefined *local_140;
  sockaddr local_138;
  byte local_128 [264];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_148 = *(long *)(param_1 + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_emu...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_2);
  }
  if (false) {
switchD_0010f515_caseD_0:
    *(undefined *)(param_1 + 0x149) = 0;
  }
  else {
    switch(*(undefined *)(param_1 + 0x149)) {
    default:
      goto switchD_0010f515_caseD_0;
    case 2:
      FUN_00111017(param_2,*(int *)(param_2 + 0x38) + 1);
      *(undefined *)((long)*(int *)(param_2 + 0x38) + *(long *)(param_2 + 0x30)) = 0;
      local_158 = (byte *)strstr(*(char **)(param_2 + 0x30),"ORT");
      if (local_158 == (byte *)0x0) {
        local_158 = (byte *)strstr(*(char **)(param_2 + 0x30),"27 Entering");
        if ((local_158 != (byte *)0x0) &&
           (local_15c = __isoc99_sscanf(local_158,&DAT_0011ddd8,&local_180,&local_17c,&local_178,
                                        &local_174,&local_170,&local_16c,local_128), 5 < local_15c))
        {
          local_168 = htonl(local_174 | local_180 << 0x18 | local_17c << 0x10 | local_178 << 8);
          uVar3 = htons((ushort)local_16c | (ushort)(local_170 << 8));
          local_164 = (socklen_t)uVar3;
          lVar9 = FUN_00115770(local_148,0,0,local_168,local_164,0x200);
          if (lVar9 != 0) {
            uVar3 = ntohs(*(uint16_t *)(lVar9 + 0x4a));
            local_170 = (uint)(uVar3 >> 8);
            local_16c = uVar3 & 0xff;
            local_168 = ntohl(*(uint32_t *)(lVar9 + 0x4c));
            local_180 = local_168 >> 0x18;
            local_17c = local_168 >> 0x10 & 0xff;
            local_178 = local_168 >> 8 & 0xff;
            local_174 = local_168 & 0xff;
            *(int *)(param_2 + 0x38) = (int)local_158 - (int)*(undefined8 *)(param_2 + 0x30);
            if (local_15c == 7) {
              pbVar8 = local_128;
            }
            else {
              pbVar8 = &DAT_0011ddb0;
            }
            if ((*(uint *)(param_2 + 0x20) & 1) == 0) {
              lVar9 = (param_2 + 0x60 + (long)*(int *)(param_2 + 0x24)) - *(long *)(param_2 + 0x30);
            }
            else {
              lVar9 = (*(long *)(param_2 + 0x58) + (long)*(int *)(param_2 + 0x24)) -
                      *(long *)(param_2 + 0x30);
            }
            iVar5 = FUN_0010831e(local_158,lVar9 - *(int *)(param_2 + 0x38),
                                 "27 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n%s",local_180,
                                 local_17c,local_178,local_174,local_170,local_16c,pbVar8);
            *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + iVar5;
          }
        }
      }
      else {
        local_15c = __isoc99_sscanf(local_158,&DAT_0011dd90,&local_180,&local_17c,&local_178,
                                    &local_174,&local_170,&local_16c,local_128);
        if (5 < local_15c) {
          local_168 = htonl(local_174 | local_180 << 0x18 | local_17c << 0x10 | local_178 << 8);
          uVar3 = htons((ushort)local_16c | (ushort)(local_170 << 8));
          local_164 = (socklen_t)uVar3;
          lVar9 = FUN_00115770(local_148,0,0,local_168,local_164,0x200);
          if (lVar9 != 0) {
            uVar3 = ntohs(*(uint16_t *)(lVar9 + 0x4a));
            local_170 = (uint)(uVar3 >> 8);
            local_16c = uVar3 & 0xff;
            local_168 = ntohl(*(uint32_t *)(lVar9 + 0x4c));
            local_180 = local_168 >> 0x18;
            local_17c = local_168 >> 0x10 & 0xff;
            local_178 = local_168 >> 8 & 0xff;
            local_174 = local_168 & 0xff;
            *(int *)(param_2 + 0x38) = (int)local_158 - (int)*(undefined8 *)(param_2 + 0x30);
            if (local_15c == 7) {
              pbVar8 = local_128;
            }
            else {
              pbVar8 = &DAT_0011ddb0;
            }
            if ((*(uint *)(param_2 + 0x20) & 1) == 0) {
              lVar9 = (param_2 + 0x60 + (long)*(int *)(param_2 + 0x24)) - *(long *)(param_2 + 0x30);
            }
            else {
              lVar9 = (*(long *)(param_2 + 0x58) + (long)*(int *)(param_2 + 0x24)) -
                      *(long *)(param_2 + 0x30);
            }
            iVar5 = FUN_0010831e(local_158,lVar9 - *(int *)(param_2 + 0x38),
                                 "ORT %d,%d,%d,%d,%d,%d\r\n%s",local_180,local_17c,local_178,
                                 local_174,local_170,local_16c,pbVar8);
            *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + iVar5;
          }
        }
      }
      break;
    case 3:
      *(undefined *)(param_1 + 0x149) = 0;
      local_164 = 0;
      for (local_160 = 0; local_160 < *(int *)(param_2 + 0x38) + -1; local_160 = local_160 + 1) {
        if ((*(char *)((long)local_160 + *(long *)(param_2 + 0x30)) < '0') ||
           ('9' < *(char *)((long)local_160 + *(long *)(param_2 + 0x30)))) goto LAB_00110968;
        local_164 = (local_164 * 10 + (int)*(char *)((long)local_160 + *(long *)(param_2 + 0x30))) -
                    0x30;
      }
      if ((*(char *)((long)*(int *)(param_2 + 0x38) + -1 + *(long *)(param_2 + 0x30)) == '\0') &&
         (local_164 != 0)) {
        uVar3 = htons((uint16_t)local_164);
        lVar9 = FUN_00115770(local_148,0,0,*(undefined4 *)(param_1 + 0xcc),uVar3,0x200);
        if (lVar9 != 0) {
          uVar3 = ntohs(*(uint16_t *)(lVar9 + 0x4a));
          if ((*(uint *)(param_2 + 0x20) & 1) == 0) {
            lVar9 = (param_2 + 0x60 + (long)*(int *)(param_2 + 0x24)) - *(long *)(param_2 + 0x30);
          }
          else {
            lVar9 = (*(long *)(param_2 + 0x58) + (long)*(int *)(param_2 + 0x24)) -
                    *(long *)(param_2 + 0x30);
          }
          uVar6 = FUN_00108442(*(undefined8 *)(param_2 + 0x30),lVar9,&DAT_0011de41,uVar3);
          *(undefined4 *)(param_2 + 0x38) = uVar6;
        }
      }
      break;
    case 4:
      FUN_00111017(param_2,*(int *)(param_2 + 0x38) + 1);
      *(undefined *)((long)*(int *)(param_2 + 0x38) + *(long *)(param_2 + 0x30)) = 0;
      local_158 = (byte *)strstr(*(char **)(param_2 + 0x30),"DCC");
      if (local_158 != (byte *)0x0) {
        iVar5 = __isoc99_sscanf(local_158,"DCC CHAT %256s %u %u",local_128,&local_168,&local_164);
        if (iVar5 == 3) {
          uVar3 = htons((uint16_t)local_164);
          uVar7 = htonl(local_168);
          lVar9 = FUN_00115770(local_148,0,0,uVar7,uVar3,0x200);
          if (lVar9 != 0) {
            *(int *)(param_2 + 0x38) = (int)local_158 - (int)*(undefined8 *)(param_2 + 0x30);
            uVar3 = ntohs(*(uint16_t *)(lVar9 + 0x4a));
            uVar7 = ntohl(*(uint32_t *)(lVar9 + 0x4c));
            if ((*(uint *)(param_2 + 0x20) & 1) == 0) {
              lVar9 = (param_2 + 0x60 + (long)*(int *)(param_2 + 0x24)) - *(long *)(param_2 + 0x30);
            }
            else {
              lVar9 = (*(long *)(param_2 + 0x58) + (long)*(int *)(param_2 + 0x24)) -
                      *(long *)(param_2 + 0x30);
            }
            iVar5 = FUN_0010831e(local_158,lVar9 - *(int *)(param_2 + 0x38),
                                 "DCC CHAT chat %lu %u%c\n",uVar7,uVar3,1);
            *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + iVar5;
          }
        }
        else {
          iVar5 = __isoc99_sscanf(local_158,"DCC SEND %256s %u %u %u",local_128,&local_168,
                                  &local_164,&local_180);
          if (iVar5 == 4) {
            uVar3 = htons((uint16_t)local_164);
            uVar7 = htonl(local_168);
            lVar9 = FUN_00115770(local_148,0,0,uVar7,uVar3,0x200);
            uVar2 = local_180;
            if (lVar9 != 0) {
              *(int *)(param_2 + 0x38) = (int)local_158 - (int)*(undefined8 *)(param_2 + 0x30);
              uVar3 = ntohs(*(uint16_t *)(lVar9 + 0x4a));
              uVar7 = ntohl(*(uint32_t *)(lVar9 + 0x4c));
              if ((*(uint *)(param_2 + 0x20) & 1) == 0) {
                lVar9 = (param_2 + 0x60 + (long)*(int *)(param_2 + 0x24)) -
                        *(long *)(param_2 + 0x30);
              }
              else {
                lVar9 = (*(long *)(param_2 + 0x58) + (long)*(int *)(param_2 + 0x24)) -
                        *(long *)(param_2 + 0x30);
              }
              iVar5 = FUN_0010831e(local_158,lVar9 - *(int *)(param_2 + 0x38),
                                   "DCC SEND %s %lu %u %u%c\n",local_128,uVar7,uVar3,uVar2,1);
              *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + iVar5;
            }
          }
          else {
            iVar5 = __isoc99_sscanf(local_158,"DCC MOVE %256s %u %u %u",local_128,&local_168,
                                    &local_164,&local_180);
            if (iVar5 == 4) {
              uVar3 = htons((uint16_t)local_164);
              uVar7 = htonl(local_168);
              lVar9 = FUN_00115770(local_148,0,0,uVar7,uVar3,0x200);
              uVar2 = local_180;
              if (lVar9 != 0) {
                *(int *)(param_2 + 0x38) = (int)local_158 - (int)*(undefined8 *)(param_2 + 0x30);
                uVar3 = ntohs(*(uint16_t *)(lVar9 + 0x4a));
                uVar7 = ntohl(*(uint32_t *)(lVar9 + 0x4c));
                if ((*(uint *)(param_2 + 0x20) & 1) == 0) {
                  lVar9 = (param_2 + 0x60 + (long)*(int *)(param_2 + 0x24)) -
                          *(long *)(param_2 + 0x30);
                }
                else {
                  lVar9 = (*(long *)(param_2 + 0x58) + (long)*(int *)(param_2 + 0x24)) -
                          *(long *)(param_2 + 0x30);
                }
                iVar5 = FUN_0010831e(local_158,lVar9 - *(int *)(param_2 + 0x38),
                                     "DCC MOVE %s %lu %u %u%c\n",local_128,uVar7,uVar3,uVar2,1);
                *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + iVar5;
              }
            }
          }
        }
      }
      break;
    case 5:
      local_158 = *(byte **)(param_2 + 0x30);
LAB_00110927:
      if (local_158 < (byte *)((long)*(int *)(param_2 + 0x38) + *(long *)(param_2 + 0x30))) {
        local_128[0] = 0x50;
        local_128[1] = 0x4e;
        local_128[2] = 0x41;
        local_128[3] = 0;
        switch(DAT_001231b4) {
        case 0:
        case 2:
        case 3:
          pbVar8 = local_158 + 1;
          bVar1 = *local_158;
          local_158 = pbVar8;
          if (bVar1 != local_128[DAT_001231b4]) {
            DAT_001231b4 = 0;
            goto LAB_00110927;
          }
          break;
        case 1:
          if (*local_158 == 0x50) {
            DAT_001231b4 = 1;
            local_158 = local_158 + 1;
          }
          else {
            pbVar8 = local_158 + 1;
            bVar1 = *local_158;
            local_158 = pbVar8;
            if (bVar1 == local_128[DAT_001231b4]) break;
            DAT_001231b4 = 0;
          }
          goto LAB_00110927;
        case 4:
          local_158 = local_158 + 1;
          break;
        case 5:
          if (local_158 == (byte *)((long)*(int *)(param_2 + 0x38) + -1 + *(long *)(param_2 + 0x30))
             ) goto LAB_00110968;
          if (local_158[1] == 2) {
            local_158 = local_158 + 8;
          }
          else {
            local_158 = local_158 + 4;
          }
          break;
        case 6:
          if (local_158 != (byte *)((long)*(int *)(param_2 + 0x38) + -1 + *(long *)(param_2 + 0x30))
             ) {
            local_164 = (uint)local_158[1] + (uint)*local_158 * 0x100;
            if (local_164 < 0x1b3a) {
              local_164 = local_164 + 0x100;
            }
            if ((0x1b39 < local_164) && (local_164 < 0x1c03)) {
              local_182 = 0x1b3a;
              goto LAB_001108a0;
            }
          }
          goto LAB_00110968;
        default:
          DAT_001231b4 = 0;
        }
        DAT_001231b4 = DAT_001231b4 + 1;
        goto LAB_00110927;
      }
      break;
    case 7:
      local_164 = 0x10;
      local_140 = (undefined *)
                  g_strstr_len(*(undefined8 *)(param_2 + 0x30),(long)*(int *)(param_2 + 0x38),
                               &DAT_0011dd73);
      if (local_140 != (undefined *)0x0) {
        *local_140 = 0;
        iVar5 = __isoc99_sscanf(*(undefined8 *)(param_2 + 0x30),"%u%*[ ,]%u",&local_180,&local_17c);
        if (iVar5 == 2) {
          uVar3 = htons((uint16_t)local_180);
          local_180 = (uint)uVar3;
          uVar3 = htons((uint16_t)local_17c);
          local_17c = (uint)uVar3;
          for (local_150 = *(undefined8 **)(local_148 + 0x1c0);
              local_150 != (undefined8 *)(local_148 + 0x1c0); local_150 = (undefined8 *)*local_150)
          {
            if ((((*(int *)((long)local_150 + 0xcc) == *(int *)(param_1 + 0xcc)) &&
                 (*(ushort *)((long)local_150 + 0xca) == local_17c)) &&
                (*(int *)((long)local_150 + 0x4c) == *(int *)(param_1 + 0x4c))) &&
               (*(ushort *)((long)local_150 + 0x4a) == local_180)) {
              iVar5 = getsockname(*(int *)(local_150 + 2),&local_138,&local_164);
              if (iVar5 == 0) {
                local_17c = (uint)(ushort)local_138.sa_data._0_2_;
              }
              break;
            }
          }
          uVar3 = ntohs((uint16_t)local_180);
          local_180 = (uint)uVar3;
          uVar3 = ntohs((uint16_t)local_17c);
          local_17c = (uint)uVar3;
          iVar5 = g_snprintf(0,0,"%d,%d\r\n",local_180,local_17c);
          FUN_00111017(param_2,iVar5 + 1);
          if ((*(uint *)(param_2 + 0x20) & 1) == 0) {
            lVar9 = (param_2 + 0x60 + (long)*(int *)(param_2 + 0x24)) - *(long *)(param_2 + 0x30);
          }
          else {
            lVar9 = (*(long *)(param_2 + 0x58) + (long)*(int *)(param_2 + 0x24)) -
                    *(long *)(param_2 + 0x30);
          }
          uVar6 = FUN_0010831e(*(undefined8 *)(param_2 + 0x30),lVar9,"%d,%d\r\n",local_180,local_17c
                              );
          *(undefined4 *)(param_2 + 0x38) = uVar6;
        }
        else {
          *local_140 = 0xd;
        }
      }
    }
  }
LAB_00110968:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 1;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
LAB_001108a0:
  if (0x1b9e < local_182) goto LAB_001108ae;
  uVar3 = htons((uint16_t)local_164);
  uVar6 = *(undefined4 *)(param_1 + 0xcc);
  uVar4 = htons(local_182);
  lVar9 = FUN_0010a32a(local_148,0,uVar4,uVar6,uVar3,0x200);
  if (lVar9 != 0) goto LAB_001108ae;
  local_182 = local_182 + 1;
  goto LAB_001108a0;
LAB_001108ae:
  if (local_182 == 0x1b9f) {
    local_182 = 0;
  }
  *local_158 = (byte)(local_182 >> 8);
  local_158[1] = (byte)local_182;
  DAT_001231b4 = 0;
  local_158 = local_158 + 1;
  goto LAB_00110968;
}



undefined8 FUN_00110985(long param_1)

{
  long lVar1;
  uint uVar2;
  undefined8 uVar3;
  long *local_20;
  
  lVar1 = *(long *)(param_1 + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_ctl...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if (*(int *)(param_1 + 0x4c) != *(int *)(lVar1 + 0x14)) {
    for (local_20 = *(long **)(lVar1 + 0x80); local_20 != (long *)0x0;
        local_20 = (long *)local_20[5]) {
      if ((*(uint *)((long)local_20 + 0x14) == (uint)*(ushort *)(param_1 + 0x4a)) &&
         (*(int *)(param_1 + 0x4c) == *(int *)(local_20 + 2))) {
        if (*local_20 != 0) {
          *(undefined4 *)(param_1 + 0x10) = 0xffffffff;
          *(long **)(param_1 + 0x18) = local_20;
          return 1;
        }
        if ((DAT_001231c0 & 2) != 0) {
          g_log("Slirp",0x80," executing %s",local_20[3]);
        }
        if (local_20[4] != 0) {
          uVar3 = FUN_0010715b(param_1,local_20[4]);
          return uVar3;
        }
        uVar3 = FUN_00106ec9(param_1,local_20[3]);
        return uVar3;
      }
    }
  }
  uVar2 = FUN_0010831e(*(undefined8 *)(param_1 + 400),
                       (ulong)*(uint *)(param_1 + 0x18c) -
                       (*(long *)(param_1 + 400) - *(long *)(param_1 + 0x1a0)),
                       "Error: No application configured.\r\n");
  *(uint *)(param_1 + 0x188) = uVar2;
  *(ulong *)(param_1 + 400) = *(long *)(param_1 + 400) + (ulong)*(uint *)(param_1 + 0x188);
  return 0;
}



void FUN_00110b93(long param_1)

{
  *(long *)(param_1 + 0xa0) = param_1 + 0x98;
  *(undefined8 *)(param_1 + 0x98) = *(undefined8 *)(param_1 + 0xa0);
  *(long *)(param_1 + 0xb0) = param_1 + 0xa8;
  *(undefined8 *)(param_1 + 0xa8) = *(undefined8 *)(param_1 + 0xb0);
  return;
}



void FUN_00110bfa(long param_1)

{
  undefined8 *puVar1;
  undefined8 *local_18;
  
  local_18 = *(undefined8 **)(param_1 + 0xa8);
  while (local_18 != (undefined8 *)(param_1 + 0xa8)) {
    puVar1 = (undefined8 *)*local_18;
    if ((*(uint *)(local_18 + 4) & 1) != 0) {
      g_free(local_18[0xb]);
    }
    g_free(local_18);
    local_18 = puVar1;
  }
  local_18 = *(undefined8 **)(param_1 + 0x98);
  while (local_18 != (undefined8 *)(param_1 + 0x98)) {
    puVar1 = (undefined8 *)*local_18;
    g_free(local_18);
    local_18 = puVar1;
  }
  return;
}



long FUN_00110cac(long param_1)

{
  long lVar1;
  uint local_1c;
  
  local_1c = 0;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"m_get...");
  }
  if (*(long *)(param_1 + 0x98) == param_1 + 0x98) {
    lVar1 = g_malloc((long)*(int *)(param_1 + 0x88) + 0x8c);
    *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 1;
    if (0x1e < *(int *)(param_1 + 0xb8)) {
      local_1c = 8;
    }
    *(long *)(lVar1 + 0x40) = param_1;
  }
  else {
    lVar1 = *(long *)(param_1 + 0x98);
    FUN_00106a6a(lVar1);
  }
  FUN_00106a33(lVar1,param_1 + 0xa8);
  *(uint *)(lVar1 + 0x20) = local_1c | 4;
  *(int *)(lVar1 + 0x24) = *(int *)(param_1 + 0x88) + 0x2c;
  *(long *)(lVar1 + 0x30) = lVar1 + 0x60;
  *(undefined4 *)(lVar1 + 0x38) = 0;
  *(undefined8 *)(lVar1 + 0x10) = 0;
  *(undefined8 *)(lVar1 + 0x18) = 0;
  *(undefined *)(lVar1 + 0x48) = 0;
  *(undefined8 *)(lVar1 + 0x50) = 0xffffffffffffffff;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",lVar1);
  }
  return lVar1;
}



void FUN_00110e00(long param_1)

{
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"m_free...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_1);
  }
  if (param_1 != 0) {
    if ((*(uint *)(param_1 + 0x20) & 4) != 0) {
      FUN_00106a6a(param_1);
    }
    if ((*(uint *)(param_1 + 0x20) & 1) != 0) {
      g_free(*(undefined8 *)(param_1 + 0x58));
    }
    if ((*(uint *)(param_1 + 0x20) & 8) == 0) {
      if ((*(uint *)(param_1 + 0x20) & 2) == 0) {
        FUN_00106a33(param_1,*(long *)(param_1 + 0x40) + 0x98);
        *(undefined4 *)(param_1 + 0x20) = 2;
      }
    }
    else {
      g_free(param_1);
      *(int *)(*(long *)(param_1 + 0x40) + 0xb8) = *(int *)(*(long *)(param_1 + 0x40) + 0xb8) + -1;
    }
  }
  return;
}



void FUN_00110f1b(long param_1,long param_2)

{
  long lVar1;
  
  if ((*(uint *)(param_1 + 0x20) & 1) == 0) {
    lVar1 = (param_1 + 0x60 + (long)*(int *)(param_1 + 0x24)) - *(long *)(param_1 + 0x30);
  }
  else {
    lVar1 = (*(long *)(param_1 + 0x58) + (long)*(int *)(param_1 + 0x24)) - *(long *)(param_1 + 0x30)
    ;
  }
  if (lVar1 - *(int *)(param_1 + 0x38) < (long)*(int *)(param_2 + 0x38)) {
    FUN_00111017(param_1,*(int *)(param_1 + 0x38) + *(int *)(param_2 + 0x38));
  }
  memcpy((void *)((long)*(int *)(param_1 + 0x38) + *(long *)(param_1 + 0x30)),
         *(void **)(param_2 + 0x30),(long)*(int *)(param_2 + 0x38));
  *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + *(int *)(param_2 + 0x38);
  FUN_00110e00(param_2);
  return;
}



void FUN_00111017(long param_1,int param_2)

{
  undefined8 uVar1;
  long lVar2;
  undefined4 local_c;
  
  if ((*(uint *)(param_1 + 0x20) & 1) == 0) {
    lVar2 = (param_1 + 0x60 + (long)*(int *)(param_1 + 0x24)) - *(long *)(param_1 + 0x30);
  }
  else {
    lVar2 = (*(long *)(param_1 + 0x58) + (long)*(int *)(param_1 + 0x24)) - *(long *)(param_1 + 0x30)
    ;
  }
  if (lVar2 <= param_2) {
    if ((*(uint *)(param_1 + 0x20) & 1) == 0) {
      local_c = (int)*(undefined8 *)(param_1 + 0x30) - ((int)param_1 + 0x60);
      uVar1 = g_malloc((long)(local_c + param_2));
      *(undefined8 *)(param_1 + 0x58) = uVar1;
      memcpy(*(void **)(param_1 + 0x58),(void *)(param_1 + 0x60),(long)*(int *)(param_1 + 0x24));
      *(uint *)(param_1 + 0x20) = *(uint *)(param_1 + 0x20) | 1;
    }
    else {
      local_c = (int)*(undefined8 *)(param_1 + 0x30) - (int)*(undefined8 *)(param_1 + 0x58);
      uVar1 = g_realloc(*(undefined8 *)(param_1 + 0x58),(long)(local_c + param_2));
      *(undefined8 *)(param_1 + 0x58) = uVar1;
    }
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x58) + (long)local_c;
    *(int *)(param_1 + 0x24) = param_2 + local_c;
  }
  return;
}



void FUN_00111173(long param_1,int param_2)

{
  if (param_1 != 0) {
    if (param_2 < 0) {
      *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + param_2;
    }
    else {
      *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + (long)param_2;
      *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) - param_2;
    }
  }
  return;
}



undefined8 FUN_001111d7(long param_1,long param_2,int param_3,int param_4)

{
  undefined8 uVar1;
  long lVar2;
  
  if ((*(uint *)(param_1 + 0x20) & 1) == 0) {
    lVar2 = (param_1 + 0x60 + (long)*(int *)(param_1 + 0x24)) - *(long *)(param_1 + 0x30);
  }
  else {
    lVar2 = (*(long *)(param_1 + 0x58) + (long)*(int *)(param_1 + 0x24)) - *(long *)(param_1 + 0x30)
    ;
  }
  if (lVar2 - *(int *)(param_1 + 0x38) < (long)param_4) {
    uVar1 = 0xffffffff;
  }
  else {
    memcpy((void *)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x38)),
           (void *)(*(long *)(param_2 + 0x30) + (long)param_3),(long)param_4);
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + param_4;
    uVar1 = 0;
  }
  return uVar1;
}



undefined8 * FUN_001112b5(long param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  undefined8 *local_10;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"dtom...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," dat = %p",param_2);
  }
  local_10 = *(undefined8 **)(param_1 + 0xa8);
  do {
    if (local_10 == (undefined8 *)(param_1 + 0xa8)) {
      if ((DAT_001231c0 & 4) != 0) {
        g_log("Slirp",0x80,"dtom failed");
      }
      return (undefined8 *)0x0;
    }
    if ((*(uint *)(local_10 + 4) & 1) == 0) {
      if (local_10 + 0xc <= param_2) {
        puVar1 = (undefined8 *)((long)local_10 + (long)*(int *)((long)local_10 + 0x24) + 0x60);
        goto joined_r0x00111397;
      }
    }
    else if ((undefined8 *)local_10[0xb] <= param_2) {
      puVar1 = (undefined8 *)((long)*(int *)((long)local_10 + 0x24) + local_10[0xb]);
joined_r0x00111397:
      if (param_2 < puVar1) {
        return local_10;
      }
    }
    local_10 = (undefined8 *)*local_10;
  } while( true );
}



undefined8 FUN_001113ef(void *param_1,void *param_2)

{
  int iVar1;
  undefined4 extraout_var;
  
  iVar1 = memcmp(param_1,param_2,0x10);
  return CONCAT71((int7)(CONCAT44(extraout_var,iVar1) >> 8),iVar1 == 0);
}



undefined4 FUN_0011141e(void *param_1,void *param_2,uint param_3)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  
  uVar2 = param_3;
  if ((int)param_3 < 0) {
    uVar2 = param_3 + 7;
  }
  iVar3 = memcmp(param_1,param_2,(long)((int)uVar2 >> 3));
  if (iVar3 == 0) {
    if ((param_3 & 7) == 0) {
      uVar5 = 1;
    }
    else {
      uVar2 = param_3;
      if ((int)param_3 < 0) {
        uVar2 = param_3 + 7;
      }
      bVar1 = (byte)((int)param_3 >> 0x1f);
      uVar4 = param_3;
      if ((int)param_3 < 0) {
        uVar4 = param_3 + 7;
      }
      iVar3 = (int)(uint)*(byte *)((long)param_2 + (long)((int)uVar4 >> 3)) >>
              (8 - (((char)param_3 + (bVar1 >> 5) & 7) - (bVar1 >> 5)) & 0x1f);
      uVar5 = CONCAT31((int3)((uint)iVar3 >> 8),
                       (int)(uint)*(byte *)((long)param_1 + (long)((int)uVar2 >> 3)) >>
                       (8 - (((char)param_3 + (bVar1 >> 5) & 7) - (bVar1 >> 5)) & 0x1f) == iVar3);
    }
  }
  else {
    uVar5 = 0;
  }
  return uVar5;
}



bool FUN_001114eb(long param_1,long param_2,uint param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  
  iVar4 = param_3 + 7;
  if ((int)(param_3 + 7) < 0) {
    iVar4 = param_3 + 0xe;
  }
  iVar2 = param_3 + 7;
  if ((int)(param_3 + 7) < 0) {
    iVar2 = param_3 + 0xe;
  }
  iVar3 = param_3 + 7;
  if ((int)(param_3 + 7) < 0) {
    iVar3 = param_3 + 0xe;
  }
  iVar4 = memcmp((void *)(param_1 + (iVar3 >> 3)),(void *)((iVar2 >> 3) + param_2),
                 (long)(0x10 - (iVar4 >> 3)));
  if (iVar4 == 0) {
    if ((param_3 & 7) == 0) {
      bVar7 = true;
    }
    else {
      uVar5 = param_3;
      if ((int)param_3 < 0) {
        uVar5 = param_3 + 7;
      }
      uVar6 = param_3;
      if ((int)param_3 < 0) {
        uVar6 = param_3 + 7;
      }
      bVar1 = (byte)((int)param_3 >> 0x1f);
      bVar7 = (~(-1 << (8 - (((char)param_3 + (bVar1 >> 5) & 7) - (bVar1 >> 5)) & 0x1f)) &
              (uint)(*(byte *)(param_2 + ((int)uVar6 >> 3)) ^ *(byte *)(param_1 + ((int)uVar5 >> 3))
                    )) == 0;
    }
  }
  else {
    bVar7 = false;
  }
  return bVar7;
}



void FUN_001115d6(undefined8 param_1,undefined8 param_2,undefined *param_3)

{
  undefined4 uStack_1c;
  
  *param_3 = 0x52;
  param_3[1] = 0x56;
  uStack_1c = (undefined4)((ulong)param_2 >> 0x20);
  *(undefined4 *)(param_3 + 2) = uStack_1c;
  return;
}



void FUN_00111613(long param_1)

{
  code *pcVar1;
  undefined8 uVar2;
  int iVar3;
  long lVar4;
  
  pcVar1 = *(code **)(*(long *)(param_1 + 0x1768) + 0x28);
  uVar2 = *(undefined8 *)(param_1 + 6000);
  lVar4 = (**(code **)(*(long *)(param_1 + 0x1768) + 0x10))(*(undefined8 *)(param_1 + 6000));
  iVar3 = g_rand_int_range(*(undefined8 *)(param_1 + 0x1750),200000,600000);
  (*pcVar1)(*(undefined8 *)(param_1 + 0x1758),lVar4 / 1000000 + (long)iVar3,uVar2);
  FUN_00111cc6(param_1);
  return;
}



void FUN_001116e0(long param_1)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  long lVar4;
  
  if (*(char *)(param_1 + 10) == '\x01') {
    uVar3 = (**(code **)(*(long *)(param_1 + 0x1768) + 0x18))
                      (FUN_00111613,param_1,*(undefined8 *)(param_1 + 6000));
    *(undefined8 *)(param_1 + 0x1758) = uVar3;
    pcVar1 = *(code **)(*(long *)(param_1 + 0x1768) + 0x28);
    uVar3 = *(undefined8 *)(param_1 + 6000);
    lVar4 = (**(code **)(*(long *)(param_1 + 0x1768) + 0x10))(*(undefined8 *)(param_1 + 6000));
    iVar2 = g_rand_int_range(*(undefined8 *)(param_1 + 0x1750),200000,600000);
    (*pcVar1)(*(undefined8 *)(param_1 + 0x1758),lVar4 / 1000000 + (long)iVar2,uVar3);
  }
  return;
}



void FUN_001117e3(long param_1)

{
  if (*(char *)(param_1 + 10) == '\x01') {
    (**(code **)(*(long *)(param_1 + 0x1768) + 0x20))
              (*(undefined8 *)(param_1 + 0x1758),*(undefined8 *)(param_1 + 6000));
  }
  return;
}



void FUN_00111834(long param_1,undefined8 param_2,long param_3)

{
  long lVar1;
  undefined8 uVar2;
  undefined *puVar3;
  uint16_t uVar4;
  undefined2 uVar5;
  long lVar6;
  
  lVar6 = FUN_00110cac(param_2);
  uVar4 = ntohs(*(uint16_t *)(param_3 + 4));
  *(uint *)(lVar6 + 0x38) = uVar4 + 0x28;
  memcpy(*(void **)(lVar6 + 0x30),*(void **)(param_1 + 0x30),(long)*(int *)(lVar6 + 0x38));
  lVar1 = *(long *)(lVar6 + 0x30);
  uVar2 = *(undefined8 *)(param_3 + 0x10);
  *(undefined8 *)(lVar1 + 0x18) = *(undefined8 *)(param_3 + 8);
  *(undefined8 *)(lVar1 + 0x20) = uVar2;
  uVar2 = *(undefined8 *)(param_3 + 0x20);
  *(undefined8 *)(lVar1 + 8) = *(undefined8 *)(param_3 + 0x18);
  *(undefined8 *)(lVar1 + 0x10) = uVar2;
  *(long *)(lVar6 + 0x30) = *(long *)(lVar6 + 0x30) + 0x28;
  puVar3 = *(undefined **)(lVar6 + 0x30);
  *puVar3 = 0x81;
  *(undefined2 *)(puVar3 + 2) = 0;
  *(long *)(lVar6 + 0x30) = *(long *)(lVar6 + 0x30) + -0x28;
  uVar5 = FUN_0010d98f(lVar6);
  *(undefined2 *)(puVar3 + 2) = uVar5;
  FUN_00107b40(0,lVar6,0);
  return;
}



void FUN_00111956(long param_1,byte param_2,byte param_3)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  byte *pbVar6;
  char cVar7;
  uint16_t uVar8;
  undefined2 uVar9;
  int iVar10;
  uint32_t uVar11;
  long lVar12;
  long in_FS_OFFSET;
  undefined8 local_58;
  undefined8 local_50;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar2 = *(long *)(param_1 + 0x40);
  lVar3 = *(long *)(param_1 + 0x30);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"icmp6_send_error...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," type = %d, code = %d",param_2,param_3);
  }
  if (*(char *)(lVar3 + 8) == -1) goto LAB_00111cb0;
  local_58 = 0;
  local_50 = 0;
  cVar7 = FUN_001113ef(lVar3 + 8,&local_58);
  if (cVar7 != '\0') goto LAB_00111cb0;
  lVar12 = FUN_00110cac(lVar2);
  lVar4 = *(long *)(lVar12 + 0x30);
  *(undefined8 *)(lVar4 + 8) = 0;
  *(undefined8 *)(lVar4 + 0x10) = 0;
  *(undefined *)(lVar4 + 8) = 0xfe;
  *(undefined *)(lVar4 + 9) = 0x80;
  *(undefined *)(lVar4 + 0x17) = 2;
  uVar5 = *(undefined8 *)(lVar3 + 0x10);
  *(undefined8 *)(lVar4 + 0x18) = *(undefined8 *)(lVar3 + 8);
  *(undefined8 *)(lVar4 + 0x20) = uVar5;
  inet_ntop(10,(void *)(lVar4 + 0x18),local_48,0x2e);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," target = %s",local_48);
  }
  *(undefined *)(lVar4 + 6) = 0x3a;
  uVar1 = (long)*(int *)(lVar2 + 0x88) - 0x30;
  iVar10 = *(int *)(param_1 + 0x38);
  if (uVar1 <= (ulong)(long)iVar10) {
    iVar10 = (int)uVar1;
  }
  uVar8 = htons((short)iVar10 + 8);
  *(uint16_t *)(lVar4 + 4) = uVar8;
  uVar8 = ntohs(*(uint16_t *)(lVar4 + 4));
  *(uint *)(lVar12 + 0x38) = uVar8 + 0x28;
  *(long *)(lVar12 + 0x30) = *(long *)(lVar12 + 0x30) + 0x28;
  pbVar6 = *(byte **)(lVar12 + 0x30);
  *pbVar6 = param_2;
  pbVar6[1] = param_3;
  pbVar6[2] = 0;
  pbVar6[3] = 0;
  if (param_2 != 4) {
    if (param_2 < 5) {
      if (param_2 == 3) {
LAB_00111bd7:
        pbVar6[4] = 0;
        pbVar6[5] = 0;
        pbVar6[6] = 0;
        pbVar6[7] = 0;
        goto LAB_00111c24;
      }
      if (param_2 < 4) {
        if (param_2 == 1) goto LAB_00111bd7;
        if (param_2 == 2) {
          uVar11 = htonl(*(uint32_t *)(lVar2 + 0x88));
          *(uint32_t *)(pbVar6 + 4) = uVar11;
          goto LAB_00111c24;
        }
      }
    }
    g_assertion_message_expr
              ("Slirp",
               "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/ip6_icmp.c"
               ,0x79,"icmp6_send_error",0);
  }
LAB_00111c24:
  *(long *)(lVar12 + 0x30) = *(long *)(lVar12 + 0x30) + 8;
  memcpy(*(void **)(lVar12 + 0x30),*(void **)(param_1 + 0x30),(long)iVar10);
  *(long *)(lVar12 + 0x30) = *(long *)(lVar12 + 0x30) + -8;
  *(long *)(lVar12 + 0x30) = *(long *)(lVar12 + 0x30) + -0x28;
  uVar9 = FUN_0010d98f(lVar12);
  *(undefined2 *)(pbVar6 + 2) = uVar9;
  FUN_00107b40(0,lVar12,0);
LAB_00111cb0:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00111cc6(long param_1)

{
  undefined8 uVar1;
  uint16_t uVar2;
  undefined2 uVar3;
  uint32_t uVar4;
  int iVar5;
  long in_FS_OFFSET;
  undefined local_64 [4];
  long local_60;
  long local_58;
  long local_50;
  undefined *local_48;
  undefined *local_40;
  undefined *local_38;
  undefined *local_30;
  undefined local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ndp_send_ra...");
  }
  local_58 = FUN_00110cac(param_1);
  local_50 = *(long *)(local_58 + 0x30);
  local_60 = 0;
  *(undefined8 *)(local_50 + 8) = 0;
  *(undefined8 *)(local_50 + 0x10) = 0;
  *(undefined *)(local_50 + 8) = 0xfe;
  *(undefined *)(local_50 + 9) = 0x80;
  *(undefined *)(local_50 + 0x17) = 2;
  *(undefined8 *)(local_50 + 0x18) = 0;
  *(undefined8 *)(local_50 + 0x20) = 0;
  *(undefined *)(local_50 + 0x18) = 0xff;
  *(undefined *)(local_50 + 0x19) = 2;
  *(undefined *)(local_50 + 0x27) = 1;
  *(undefined *)(local_50 + 6) = 0x3a;
  *(long *)(local_58 + 0x30) = *(long *)(local_58 + 0x30) + 0x28;
  local_48 = *(undefined **)(local_58 + 0x30);
  *local_48 = 0x86;
  local_48[1] = 0;
  *(undefined2 *)(local_48 + 2) = 0;
  local_48[4] = 0x40;
  local_48[5] = local_48[5] & 0x7f;
  local_48[5] = local_48[5] & 0xbf;
  local_48[5] = local_48[5] & 0xc0;
  uVar2 = htons(0x708);
  *(uint16_t *)(local_48 + 6) = uVar2;
  uVar4 = htonl(0);
  *(uint32_t *)(local_48 + 8) = uVar4;
  uVar4 = htonl(0);
  *(uint32_t *)(local_48 + 0xc) = uVar4;
  *(long *)(local_58 + 0x30) = *(long *)(local_58 + 0x30) + 0x10;
  local_60 = local_60 + 0x10;
  local_40 = *(undefined **)(local_58 + 0x30);
  *local_40 = 1;
  local_40[1] = 1;
  FUN_001115d6(*(undefined8 *)(local_50 + 8),*(undefined8 *)(local_50 + 0x10),local_40 + 2);
  *(long *)(local_58 + 0x30) = *(long *)(local_58 + 0x30) + 8;
  local_60 = local_60 + 8;
  local_38 = *(undefined **)(local_58 + 0x30);
  *local_38 = 3;
  local_38[1] = 4;
  local_38[2] = *(undefined *)(param_1 + 0x28);
  local_38[3] = local_38[3] | 0x80;
  local_38[3] = local_38[3] | 0x40;
  local_38[3] = local_38[3] & 0xc0;
  uVar4 = htonl(0x15180);
  *(uint32_t *)(local_38 + 4) = uVar4;
  uVar4 = htonl(0x3840);
  *(uint32_t *)(local_38 + 8) = uVar4;
  *(undefined4 *)(local_38 + 0xc) = 0;
  uVar1 = *(undefined8 *)(param_1 + 0x20);
  *(undefined8 *)(local_38 + 0x10) = *(undefined8 *)(param_1 + 0x18);
  *(undefined8 *)(local_38 + 0x18) = uVar1;
  *(long *)(local_58 + 0x30) = *(long *)(local_58 + 0x30) + 0x20;
  local_60 = local_60 + 0x20;
  iVar5 = FUN_00103257(local_28,local_64);
  if (-1 < iVar5) {
    local_30 = *(undefined **)(local_58 + 0x30);
    *local_30 = 0x19;
    local_30[1] = 3;
    *(undefined2 *)(local_30 + 2) = 0;
    uVar4 = htonl(1200000);
    *(uint32_t *)(local_30 + 4) = uVar4;
    uVar1 = *(undefined8 *)(param_1 + 0x4c);
    *(undefined8 *)(local_30 + 8) = *(undefined8 *)(param_1 + 0x44);
    *(undefined8 *)(local_30 + 0x10) = uVar1;
    *(long *)(local_58 + 0x30) = *(long *)(local_58 + 0x30) + 0x18;
    local_60 = local_60 + 0x18;
  }
  uVar2 = htons((uint16_t)local_60);
  *(uint16_t *)(local_50 + 4) = uVar2;
  *(long *)(local_58 + 0x30) = *(long *)(local_58 + 0x30) + (-0x28 - local_60);
  *(int *)(local_58 + 0x38) = (int)local_60 + 0x28;
  uVar3 = FUN_0010d98f(local_58);
  *(undefined2 *)(local_48 + 2) = uVar3;
  FUN_00107b40(0,local_58,0);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_00112055(long param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 uVar1;
  uint16_t uVar2;
  undefined2 uVar3;
  long in_FS_OFFSET;
  undefined8 local_88;
  undefined8 local_80;
  long local_70;
  long local_68;
  long local_60;
  undefined *local_58;
  undefined *local_50;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_88 = param_2;
  local_80 = param_3;
  local_70 = param_1;
  inet_ntop(10,&local_88,local_48,0x2e);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ndp_send_ns...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," target = %s",local_48);
  }
  local_68 = FUN_00110cac(local_70);
  local_60 = *(long *)(local_68 + 0x30);
  uVar1 = *(undefined8 *)(local_70 + 0x34);
  *(undefined8 *)(local_60 + 8) = *(undefined8 *)(local_70 + 0x2c);
  *(undefined8 *)(local_60 + 0x10) = uVar1;
  *(undefined *)(local_60 + 0x18) = 0xff;
  *(undefined *)(local_60 + 0x19) = 2;
  *(undefined *)(local_60 + 0x1a) = 0;
  *(undefined *)(local_60 + 0x1b) = 0;
  *(undefined *)(local_60 + 0x1c) = 0;
  *(undefined *)(local_60 + 0x1d) = 0;
  *(undefined *)(local_60 + 0x1e) = 0;
  *(undefined *)(local_60 + 0x1f) = 0;
  *(undefined *)(local_60 + 0x20) = 0;
  *(undefined *)(local_60 + 0x21) = 0;
  *(undefined *)(local_60 + 0x22) = 0;
  *(undefined *)(local_60 + 0x23) = 1;
  *(undefined *)(local_60 + 0x24) = 0xff;
  *(undefined *)(local_60 + 0x25) = 0;
  *(undefined *)(local_60 + 0x26) = 0;
  *(undefined *)(local_60 + 0x27) = 0;
  memcpy((void *)(local_60 + 0x25),(void *)((long)&local_80 + 5),3);
  *(undefined *)(local_60 + 6) = 0x3a;
  uVar2 = htons(0x20);
  *(uint16_t *)(local_60 + 4) = uVar2;
  uVar2 = ntohs(*(uint16_t *)(local_60 + 4));
  *(uint *)(local_68 + 0x38) = uVar2 + 0x28;
  *(long *)(local_68 + 0x30) = *(long *)(local_68 + 0x30) + 0x28;
  local_58 = *(undefined **)(local_68 + 0x30);
  *local_58 = 0x87;
  local_58[1] = 0;
  *(undefined2 *)(local_58 + 2) = 0;
  *(undefined4 *)(local_58 + 4) = 0;
  *(undefined8 *)(local_58 + 8) = local_88;
  *(undefined8 *)(local_58 + 0x10) = local_80;
  *(long *)(local_68 + 0x30) = *(long *)(local_68 + 0x30) + 0x18;
  local_50 = *(undefined **)(local_68 + 0x30);
  *local_50 = 1;
  local_50[1] = 1;
  FUN_001115d6(*(undefined8 *)(local_70 + 0x2c),*(undefined8 *)(local_70 + 0x34),local_50 + 2);
  *(long *)(local_68 + 0x30) = *(long *)(local_68 + 0x30) + -0x18;
  *(long *)(local_68 + 0x30) = *(long *)(local_68 + 0x30) + -0x28;
  uVar3 = FUN_0010d98f(local_68);
  *(undefined2 *)(local_58 + 2) = uVar3;
  FUN_00107b40(0,local_68,1);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_0011231d(undefined8 param_1,long param_2,long param_3)

{
  long lVar1;
  undefined8 uVar2;
  undefined *puVar3;
  undefined *puVar4;
  char cVar5;
  uint16_t uVar6;
  undefined2 uVar7;
  long lVar8;
  long in_FS_OFFSET;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar8 = FUN_00110cac(param_1);
  lVar1 = *(long *)(lVar8 + 0x30);
  uVar2 = *(undefined8 *)(param_3 + 0x10);
  *(undefined8 *)(lVar1 + 8) = *(undefined8 *)(param_3 + 8);
  *(undefined8 *)(lVar1 + 0x10) = uVar2;
  local_28 = 0;
  local_20 = 0;
  cVar5 = FUN_001113ef(param_2 + 8,&local_28);
  if (cVar5 == '\0') {
    uVar2 = *(undefined8 *)(param_2 + 0x10);
    *(undefined8 *)(lVar1 + 0x18) = *(undefined8 *)(param_2 + 8);
    *(undefined8 *)(lVar1 + 0x20) = uVar2;
  }
  else {
    *(undefined8 *)(lVar1 + 0x18) = 0;
    *(undefined8 *)(lVar1 + 0x20) = 0;
    *(undefined *)(lVar1 + 0x18) = 0xff;
    *(undefined *)(lVar1 + 0x19) = 2;
    *(undefined *)(lVar1 + 0x27) = 1;
  }
  *(undefined *)(lVar1 + 6) = 0x3a;
  uVar6 = htons(0x20);
  *(uint16_t *)(lVar1 + 4) = uVar6;
  uVar6 = ntohs(*(uint16_t *)(lVar1 + 4));
  *(uint *)(lVar8 + 0x38) = uVar6 + 0x28;
  *(long *)(lVar8 + 0x30) = *(long *)(lVar8 + 0x30) + 0x28;
  puVar3 = *(undefined **)(lVar8 + 0x30);
  *puVar3 = 0x88;
  puVar3[1] = 0;
  *(undefined2 *)(puVar3 + 2) = 0;
  puVar3[4] = puVar3[4] | 0x80;
  puVar3[4] = puVar3[4] & 0xbf | (*(char *)(lVar1 + 0x18) != -1) << 6;
  puVar3[4] = puVar3[4] | 0x20;
  puVar3[4] = puVar3[4] & 0xe0;
  *(uint *)(puVar3 + 4) = *(uint *)(puVar3 + 4) & 0xff;
  uVar2 = *(undefined8 *)(param_3 + 0x10);
  *(undefined8 *)(puVar3 + 8) = *(undefined8 *)(param_3 + 8);
  *(undefined8 *)(puVar3 + 0x10) = uVar2;
  *(long *)(lVar8 + 0x30) = *(long *)(lVar8 + 0x30) + 0x18;
  puVar4 = *(undefined **)(lVar8 + 0x30);
  *puVar4 = 2;
  puVar4[1] = 1;
  FUN_001115d6(*(undefined8 *)(puVar3 + 8),*(undefined8 *)(puVar3 + 0x10),puVar4 + 2);
  *(long *)(lVar8 + 0x30) = *(long *)(lVar8 + 0x30) + -0x18;
  *(long *)(lVar8 + 0x30) = *(long *)(lVar8 + 0x30) + -0x28;
  uVar7 = FUN_0010d98f(lVar8);
  *(undefined2 *)(puVar3 + 2) = uVar7;
  FUN_00107b40(0,lVar8,0);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_0011258d(long param_1,long param_2,long param_3,undefined *param_4)

{
  long lVar1;
  char cVar2;
  uint16_t uVar3;
  long in_FS_OFFSET;
  undefined8 local_58;
  undefined8 local_50;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0xe;
  *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0xe;
  lVar1 = *(long *)(param_1 + 0x30);
  *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -0xe;
  *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 0xe;
  switch(*param_4) {
  case 0x85:
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," type = Router Solicitation...");
    }
    if (((*(char *)(param_3 + 7) == -1) && (param_4[1] == '\0')) &&
       (uVar3 = ntohs(*(uint16_t *)(param_3 + 4)), 7 < uVar3)) {
      FUN_00116ee3(param_2,*(undefined8 *)(param_3 + 8),*(undefined8 *)(param_3 + 0x10),lVar1 + 6);
      FUN_00111cc6(param_2);
    }
    break;
  case 0x86:
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," type = Router Advertisement...");
    }
    (**(code **)(*(long *)(param_2 + 0x1768) + 8))
              ("Warning: guest sent NDP RA, but shouldn\'t",*(undefined8 *)(param_2 + 6000));
    break;
  case 0x87:
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," type = Neighbor Solicitation...");
    }
    if (((*(char *)(param_3 + 7) == -1) && (param_4[1] == '\0')) &&
       ((param_4[8] != -1 && (uVar3 = ntohs(*(uint16_t *)(param_3 + 4)), 0x17 < uVar3)))) {
      local_58 = 0;
      local_50 = 0;
      cVar2 = FUN_001113ef(param_3 + 8,&local_58);
      if (cVar2 == '\x01') {
        local_48 = 0xff;
        local_47 = 2;
        local_46 = 0;
        local_45 = 0;
        local_44 = 0;
        local_43 = 0;
        local_42 = 0;
        local_41 = 0;
        local_40 = 0;
        local_3f = 0;
        local_3e = 0;
        local_3d = 1;
        local_3c = 0xff;
        local_3b = 0;
        local_3a = 0;
        local_39 = 0;
        cVar2 = FUN_0011141e(param_3 + 0x18,&local_48,0x68);
        if (cVar2 == '\0') break;
      }
      cVar2 = FUN_0011141e(param_4 + 8,param_2 + 0x18,*(undefined *)(param_2 + 0x28));
      if ((cVar2 == '\0') ||
         (cVar2 = FUN_001114eb(param_4 + 8,param_2 + 0x2c,*(undefined *)(param_2 + 0x28)),
         cVar2 == '\0')) {
        local_38 = 0x80fe;
        local_30 = 0x200000000000000;
        cVar2 = FUN_0011141e(param_4 + 8,&local_38,0x40);
        if (((cVar2 == '\0') ||
            (cVar2 = FUN_001114eb(param_4 + 8,param_2 + 0x2c,0x40), cVar2 == '\0')) &&
           ((cVar2 = FUN_0011141e(param_4 + 8,param_2 + 0x18,*(undefined *)(param_2 + 0x28)),
            cVar2 == '\0' ||
            (cVar2 = FUN_001114eb(param_4 + 8,param_2 + 0x44,*(undefined *)(param_2 + 0x28)),
            cVar2 == '\0')))) {
          local_28 = 0x80fe;
          local_20 = 0x200000000000000;
          cVar2 = FUN_0011141e(param_4 + 8,&local_28,0x40);
          if ((cVar2 == '\0') ||
             (cVar2 = FUN_001114eb(param_4 + 8,param_2 + 0x44,0x40), cVar2 == '\0')) break;
        }
      }
      FUN_00116ee3(param_2,*(undefined8 *)(param_3 + 8),*(undefined8 *)(param_3 + 0x10),lVar1 + 6);
      FUN_0011231d(param_2,param_3,param_4);
    }
    break;
  case 0x88:
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," type = Neighbor Advertisement...");
    }
    if ((((*(char *)(param_3 + 7) == -1) && (param_4[1] == '\0')) &&
        (uVar3 = ntohs(*(uint16_t *)(param_3 + 4)), 0x17 < uVar3)) &&
       ((param_4[8] != -1 && ((*(char *)(param_3 + 0x18) != -1 || ((param_4[4] & 0x40) == 0)))))) {
      FUN_00116ee3(param_2,*(undefined8 *)(param_3 + 8),*(undefined8 *)(param_3 + 0x10),lVar1 + 6);
    }
    break;
  case 0x89:
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," type = Redirect...");
    }
    (**(code **)(*(long *)(param_2 + 0x1768) + 8))
              ("Warning: guest sent NDP REDIRECT, but shouldn\'t",*(undefined8 *)(param_2 + 6000));
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00112b19(long param_1)

{
  byte bVar1;
  long lVar2;
  long lVar3;
  byte *pbVar4;
  char cVar5;
  uint16_t uVar6;
  int iVar7;
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar2 = *(long *)(param_1 + 0x30);
  lVar3 = *(long *)(param_1 + 0x40);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"icmp6_input...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m_len = %d",*(undefined4 *)(param_1 + 0x38));
  }
  uVar6 = ntohs(*(uint16_t *)(lVar2 + 4));
  if ((3 < uVar6) && (iVar7 = FUN_0010d98f(param_1), iVar7 == 0)) {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -0x28;
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 0x28;
    pbVar4 = *(byte **)(param_1 + 0x30);
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0x28;
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0x28;
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," icmp6_type = %d",*pbVar4);
    }
    bVar1 = *pbVar4;
    if (bVar1 == 0x80) {
      cVar5 = FUN_0011141e(lVar2 + 0x18,lVar3 + 0x18,*(undefined *)(lVar3 + 0x28));
      if ((cVar5 == '\0') ||
         (cVar5 = FUN_001114eb(lVar2 + 0x18,lVar3 + 0x2c,*(undefined *)(lVar3 + 0x28)),
         cVar5 == '\0')) {
        local_38 = 0x80fe;
        local_30 = 0x200000000000000;
        cVar5 = FUN_0011141e(lVar2 + 0x18,&local_38,0x40);
        if (((cVar5 == '\0') ||
            (cVar5 = FUN_001114eb(lVar2 + 0x18,lVar3 + 0x2c,0x40), cVar5 == '\0')) &&
           ((cVar5 = FUN_0011141e(lVar2 + 0x18,lVar3 + 0x18,*(undefined *)(lVar3 + 0x28)),
            cVar5 == '\0' ||
            (cVar5 = FUN_001114eb(lVar2 + 0x18,lVar3 + 0x44,*(undefined *)(lVar3 + 0x28)),
            cVar5 == '\0')))) {
          local_28 = 0x80fe;
          local_20 = 0x200000000000000;
          cVar5 = FUN_0011141e(lVar2 + 0x18,&local_28,0x40);
          if ((cVar5 == '\0') ||
             (cVar5 = FUN_001114eb(lVar2 + 0x18,lVar3 + 0x44,0x40), cVar5 == '\0')) {
            g_log("Slirp",8,"external icmpv6 not supported yet");
            goto LAB_00112ea6;
          }
        }
      }
      FUN_00111834(param_1,lVar3,lVar2,pbVar4);
    }
    else if ((0x7f < bVar1) && (bVar1 - 0x85 < 5)) {
      FUN_0011258d(param_1,lVar3,lVar2,pbVar4);
    }
  }
LAB_00112ea6:
  FUN_00110e00(param_1);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00112ec9(long param_1)

{
  long lVar1;
  undefined8 *puVar2;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_fasttimo...");
  }
  puVar2 = *(undefined8 **)(param_1 + 0x1c0);
  if (puVar2 != (undefined8 *)0x0) {
    for (; puVar2 != (undefined8 *)(param_1 + 0x1c0); puVar2 = (undefined8 *)*puVar2) {
      lVar1 = puVar2[0x2a];
      if ((lVar1 != 0) && ((*(ushort *)(lVar1 + 0x24) & 2) != 0)) {
        *(ushort *)(lVar1 + 0x24) = *(ushort *)(lVar1 + 0x24) & 0xfffd;
        *(ushort *)(lVar1 + 0x24) = *(ushort *)(lVar1 + 0x24) | 1;
        FUN_00105b44(lVar1);
      }
    }
  }
  return;
}



void FUN_00112f6e(long param_1)

{
  long *plVar1;
  long lVar2;
  int iVar3;
  long *plVar4;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_slowtimo...");
  }
  plVar1 = *(long **)(param_1 + 0x1c0);
  if (*(long **)(param_1 + 0x1c0) != (long *)0x0) {
LAB_0011307b:
    plVar4 = plVar1;
    if (plVar4 != (long *)(param_1 + 0x1c0)) {
      plVar1 = (long *)*plVar4;
      lVar2 = plVar4[0x2a];
      if (lVar2 != 0) {
        for (iVar3 = 0; iVar3 < 4; iVar3 = iVar3 + 1) {
          if (((*(short *)(lVar2 + 2 + ((long)iVar3 + 8) * 2) != 0) &&
              (*(short *)(lVar2 + 2 + ((long)iVar3 + 8) * 2) =
                    *(short *)(lVar2 + 2 + ((long)iVar3 + 8) * 2) + -1,
              *(short *)(lVar2 + 2 + ((long)iVar3 + 8) * 2) == 0)) &&
             (FUN_00113102(lVar2,iVar3), plVar4 != (long *)plVar1[1])) goto LAB_0011307b;
        }
        *(short *)(lVar2 + 0xb4) = *(short *)(lVar2 + 0xb4) + 1;
        if (*(short *)(lVar2 + 0xb6) != 0) {
          *(short *)(lVar2 + 0xb6) = *(short *)(lVar2 + 0xb6) + 1;
        }
      }
      goto LAB_0011307b;
    }
    *(int *)(param_1 + 0x370) = *(int *)(param_1 + 0x370) + 64000;
    *(int *)(param_1 + 0x374) = *(int *)(param_1 + 0x374) + 1;
  }
  return;
}



void FUN_001130cf(long param_1)

{
  int iVar1;
  
  for (iVar1 = 0; iVar1 < 4; iVar1 = iVar1 + 1) {
    *(undefined2 *)(param_1 + 2 + ((long)iVar1 + 8) * 2) = 0;
  }
  return;
}



long FUN_00113102(long param_1,int param_2)

{
  ushort uVar1;
  uint uVar2;
  long lVar3;
  uint local_1c;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_timers...");
  }
  if (param_2 == 3) {
    if ((*(short *)(param_1 + 0x10) == 10) || (0x4b0 < *(short *)(param_1 + 0xb4))) {
      param_1 = FUN_0010e72f(param_1);
    }
    else {
      *(undefined2 *)(param_1 + 0x18) = 0x96;
    }
  }
  else if (param_2 < 4) {
    if (param_2 == 2) {
      if (3 < *(short *)(param_1 + 0x10)) {
        if ((DAT_001231cc == '\0') || (5 < *(short *)(param_1 + 0x10))) {
          *(undefined2 *)(param_1 + 0x16) = 0x3840;
          return param_1;
        }
        if (*(short *)(param_1 + 0xb4) < 0x3cf0) {
          FUN_0010dde3(param_1,param_1 + 0x28,0,*(undefined4 *)(param_1 + 0x98),
                       *(int *)(param_1 + 0x78) + -1,0,
                       *(undefined2 *)(*(long *)(param_1 + 0x70) + 0x48));
          *(undefined2 *)(param_1 + 0x16) = 0x96;
          return param_1;
        }
      }
      param_1 = FUN_0010e65c(param_1,0);
    }
    else if (param_2 < 3) {
      if (param_2 == 0) {
        *(short *)(param_1 + 0x1a) = *(short *)(param_1 + 0x1a) + 1;
        if (0xc < *(short *)(param_1 + 0x1a)) {
          *(ushort *)(param_1 + 0x20) = *(ushort *)(param_1 + 0x20) >> 1;
          if (*(ushort *)(param_1 + 0x20) < 0x20) {
            *(undefined2 *)(param_1 + 0x1a) = 0xc;
            lVar3 = FUN_0010e65c(param_1,(int)*(short *)(param_1 + 0xca));
            return lVar3;
          }
          *(undefined2 *)(param_1 + 0x1a) = 6;
        }
        *(short *)(param_1 + 0x1c) =
             ((*(short *)(param_1 + 0xbc) >> 3) + *(short *)(param_1 + 0xbe)) *
             (short)*(undefined4 *)(&DAT_0011e280 + (long)(int)*(short *)(param_1 + 0x1a) * 4);
        if (*(short *)(param_1 + 0x1c) < *(short *)(param_1 + 0xc0)) {
          *(undefined2 *)(param_1 + 0x1c) = *(undefined2 *)(param_1 + 0xc0);
        }
        else if (0x18 < *(short *)(param_1 + 0x1c)) {
          *(undefined2 *)(param_1 + 0x1c) = 0x18;
        }
        *(undefined2 *)(param_1 + 0x12) = *(undefined2 *)(param_1 + 0x1c);
        if (3 < *(short *)(param_1 + 0x1a)) {
          *(short *)(param_1 + 0xbe) =
               (*(short *)(param_1 + 0xbc) >> 3) + *(short *)(param_1 + 0xbe);
          *(undefined2 *)(param_1 + 0xbc) = 0;
        }
        *(undefined4 *)(param_1 + 0x7c) = *(undefined4 *)(param_1 + 0x78);
        *(undefined2 *)(param_1 + 0xb6) = 0;
        uVar2 = *(uint *)(param_1 + 0x90);
        if (*(uint *)(param_1 + 0xac) <= *(uint *)(param_1 + 0x90)) {
          uVar2 = *(uint *)(param_1 + 0xac);
        }
        uVar1 = *(ushort *)(param_1 + 0x20);
        local_1c = (uVar2 >> 1) / (uint)uVar1;
        if (local_1c < 2) {
          local_1c = 2;
        }
        *(uint *)(param_1 + 0xac) = (uint)*(ushort *)(param_1 + 0x20);
        *(uint *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0x20) * local_1c;
        *(undefined2 *)(param_1 + 0x1e) = 0;
        FUN_00105b44(param_1,(ulong)uVar1,(ulong)(uVar2 >> 1) % (ulong)uVar1);
      }
      else if (param_2 == 1) {
        FUN_00106923(param_1);
        *(undefined *)(param_1 + 0x22) = 1;
        FUN_00105b44(param_1);
        *(undefined *)(param_1 + 0x22) = 0;
      }
    }
  }
  return param_1;
}



void FUN_001133cd(int param_1)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 1;
  setsockopt(param_1,1,2,&local_14,4);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



undefined8 FUN_00113425(void *param_1,void *param_2)

{
  int iVar1;
  undefined4 extraout_var;
  
  iVar1 = memcmp(param_1,param_2,0x10);
  return CONCAT71((int7)(CONCAT44(extraout_var,iVar1) >> 8),iVar1 == 0);
}



undefined4 FUN_00113454(void *param_1,void *param_2,uint param_3)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  
  uVar2 = param_3;
  if ((int)param_3 < 0) {
    uVar2 = param_3 + 7;
  }
  iVar3 = memcmp(param_1,param_2,(long)((int)uVar2 >> 3));
  if (iVar3 == 0) {
    if ((param_3 & 7) == 0) {
      uVar5 = 1;
    }
    else {
      uVar2 = param_3;
      if ((int)param_3 < 0) {
        uVar2 = param_3 + 7;
      }
      bVar1 = (byte)((int)param_3 >> 0x1f);
      uVar4 = param_3;
      if ((int)param_3 < 0) {
        uVar4 = param_3 + 7;
      }
      iVar3 = (int)(uint)*(byte *)((long)param_2 + (long)((int)uVar4 >> 3)) >>
              (8 - (((char)param_3 + (bVar1 >> 5) & 7) - (bVar1 >> 5)) & 0x1f);
      uVar5 = CONCAT31((int3)((uint)iVar3 >> 8),
                       (int)(uint)*(byte *)((long)param_1 + (long)((int)uVar2 >> 3)) >>
                       (8 - (((char)param_3 + (bVar1 >> 5) & 7) - (bVar1 >> 5)) & 0x1f) == iVar3);
    }
  }
  else {
    uVar5 = 0;
  }
  return uVar5;
}



undefined8 FUN_00113521(short *param_1,short *param_2)

{
  char cVar1;
  undefined8 uVar2;
  
  if (*param_1 == *param_2) {
    if (*param_1 == 2) {
      if ((*(int *)(param_1 + 2) == *(int *)(param_2 + 2)) && (param_1[1] == param_2[1])) {
        uVar2 = 1;
      }
      else {
        uVar2 = 0;
      }
    }
    else if (*param_1 == 10) {
      cVar1 = FUN_00113425(param_1 + 4,param_2 + 4);
      if ((cVar1 == '\0') || (param_1[1] != param_2[1])) {
        uVar2 = 0;
      }
      else {
        uVar2 = 1;
      }
    }
    else {
      uVar2 = g_assertion_message_expr
                        ("Slirp",
                         "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.h"
                         ,0x7a,"sockaddr_equal",0);
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



undefined8 FUN_00113625(short *param_1)

{
  undefined8 uVar1;
  
  if (*param_1 == 2) {
    uVar1 = 0x10;
  }
  else if (*param_1 == 10) {
    uVar1 = 0x1c;
  }
  else {
    uVar1 = g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.h"
                       ,0x88,"sockaddr_size",0);
  }
  return uVar1;
}



undefined8 * FUN_0011367c(long *param_1,undefined8 *param_2,undefined8 param_3,long param_4)

{
  int iVar1;
  undefined8 *puVar2;
  undefined8 *local_10;
  
  puVar2 = (undefined8 *)*param_1;
  if (((puVar2 == param_2) || (iVar1 = FUN_00113521(puVar2 + 0x19,param_3), iVar1 == 0)) ||
     ((param_4 != 0 && (iVar1 = FUN_00113521(puVar2 + 9,param_4), iVar1 == 0)))) {
    for (local_10 = (undefined8 *)*param_2; local_10 != param_2; local_10 = (undefined8 *)*local_10)
    {
      iVar1 = FUN_00113521(local_10 + 0x19,param_3);
      if ((iVar1 != 0) &&
         ((param_4 == 0 || (iVar1 = FUN_00113521(local_10 + 9,param_4), iVar1 != 0)))) {
        *param_1 = (long)local_10;
        return local_10;
      }
    }
    puVar2 = (undefined8 *)0x0;
  }
  return puVar2;
}



void * FUN_0011376d(undefined8 param_1)

{
  void *__s;
  
  __s = (void *)g_malloc_n(1,0x1a8);
  memset(__s,0,0x1a8);
  *(undefined4 *)((long)__s + 0x14c) = 1;
  *(undefined4 *)((long)__s + 0x10) = 0xffffffff;
  *(undefined8 *)((long)__s + 0x28) = param_1;
  *(undefined4 *)((long)__s + 0x20) = 0xffffffff;
  return __s;
}



void FUN_001137dc(long param_1,undefined8 *param_2)

{
  undefined8 *local_18;
  undefined8 *local_10;
  
  for (local_18 = (undefined8 *)*param_2; local_18 != param_2; local_18 = (undefined8 *)*local_18) {
    if (param_1 == local_18[5]) {
      local_18[5] = 0;
      for (local_10 = (undefined8 *)local_18[2]; local_10 != local_18;
          local_10 = (undefined8 *)local_10[2]) {
        local_10[5] = 0;
      }
    }
  }
  return;
}



void FUN_0011385c(long *param_1)

{
  long lVar1;
  
  lVar1 = param_1[5];
  FUN_001137dc(param_1,lVar1 + 0xc0);
  FUN_001137dc(param_1,lVar1 + 0xd0);
  if (param_1 == *(long **)(lVar1 + 0x368)) {
    *(long *)(lVar1 + 0x368) = lVar1 + 0x1c0;
  }
  else if (param_1 == *(long **)(lVar1 + 0x520)) {
    *(long *)(lVar1 + 0x520) = lVar1 + 0x378;
  }
  else if (param_1 == *(long **)(lVar1 + 0x6d0)) {
    *(long *)(lVar1 + 0x6d0) = lVar1 + 0x528;
  }
  FUN_00110e00(param_1[6]);
  if ((*param_1 != 0) && (param_1[1] != 0)) {
    FUN_00106a6a(param_1);
  }
  if (param_1[0x2a] != 0) {
    g_free(param_1[0x2a]);
  }
  g_free(param_1);
  return;
}



long FUN_0011398c(long param_1,undefined8 *param_2,int *param_3)

{
  uint uVar1;
  long lVar2;
  int iVar3;
  int local_24;
  
  iVar3 = *(int *)(param_1 + 0x18c) - *(int *)(param_1 + 0x188);
  uVar1 = (uint)*(ushort *)(*(long *)(param_1 + 0x150) + 0x20);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"sopreprbuf...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if (iVar3 < 1) {
    lVar2 = 0;
  }
  else {
    *param_2 = *(undefined8 *)(param_1 + 400);
    param_2[2] = 0;
    param_2[3] = 0;
    if (*(ulong *)(param_1 + 400) < *(ulong *)(param_1 + 0x198)) {
      param_2[1] = *(long *)(param_1 + 0x198) - *(long *)(param_1 + 400);
      if ((ulong)(long)iVar3 < (ulong)param_2[1]) {
        param_2[1] = (long)iVar3;
      }
      if ((ulong)(long)(int)uVar1 < (ulong)param_2[1]) {
        param_2[1] = param_2[1] - (ulong)param_2[1] % (ulong)(long)(int)uVar1;
      }
      local_24 = 1;
    }
    else {
      param_2[1] = (*(long *)(param_1 + 0x1a0) + (ulong)*(uint *)(param_1 + 0x18c)) -
                   *(long *)(param_1 + 400);
      if ((ulong)(long)iVar3 < (ulong)param_2[1]) {
        param_2[1] = (long)iVar3;
      }
      iVar3 = iVar3 - (int)param_2[1];
      if (iVar3 == 0) {
        if ((ulong)(long)(int)uVar1 < (ulong)param_2[1]) {
          param_2[1] = param_2[1] - (ulong)param_2[1] % (ulong)(long)(int)uVar1;
        }
        local_24 = 1;
      }
      else {
        param_2[2] = *(undefined8 *)(param_1 + 0x1a0);
        param_2[3] = *(long *)(param_1 + 0x198) - *(long *)(param_1 + 0x1a0);
        if ((ulong)(long)iVar3 < (ulong)param_2[3]) {
          param_2[3] = (long)iVar3;
        }
        iVar3 = (int)param_2[3] + (int)param_2[1];
        if ((int)uVar1 < iVar3) {
          iVar3 = iVar3 % (int)uVar1;
          if ((ulong)(long)iVar3 < (ulong)param_2[3]) {
            param_2[3] = param_2[3] - (long)iVar3;
            local_24 = 2;
          }
          else {
            param_2[1] = param_2[1] - (long)(iVar3 - (int)param_2[3]);
            local_24 = 1;
          }
        }
        else {
          local_24 = 2;
        }
      }
    }
    if (param_3 != (int *)0x0) {
      *param_3 = local_24;
    }
    lVar2 = param_2[3] * (long)(local_24 + -1) + param_2[1];
  }
  return lVar2;
}



int FUN_00113d10(long param_1)

{
  int iVar1;
  ssize_t sVar2;
  int *piVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  int local_fc;
  int local_f8 [4];
  int local_e8;
  uint local_e4;
  int *local_e0;
  long local_d8;
  sockaddr *local_d0;
  void *local_c8;
  size_t local_c0;
  void *local_b8;
  size_t local_b0;
  sockaddr local_a8 [8];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_e0 = (int *)(param_1 + 0x188);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"soread...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  local_d8 = FUN_0011398c(param_1,&local_c8,&local_fc);
  if (local_d8 == 0) {
                    // WARNING: Subroutine does not return
    __assert_fail("buf_len != 0",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.c"
                  ,0xb7,"soread");
  }
  sVar2 = recv(*(int *)(param_1 + 0x10),local_c8,local_c0,0);
  local_f8[3] = (int)sVar2;
  if (local_f8[3] < 1) {
    if ((local_f8[3] < 0) &&
       ((piVar3 = __errno_location(), *piVar3 == 4 || (piVar3 = __errno_location(), *piVar3 == 0xb))
       )) {
      iVar1 = 0;
    }
    else {
      local_f8[1] = 4;
      local_d0 = local_a8;
      local_f8[2] = 0x80;
      piVar3 = __errno_location();
      local_f8[0] = *piVar3;
      if (local_f8[3] == 0) {
        local_e4 = *(uint *)(param_1 + 0x14c) & 0x10;
        if ((local_e4 == 0) &&
           (iVar1 = getpeername(*(int *)(param_1 + 0x10),local_d0,(socklen_t *)(local_f8 + 2)),
           iVar1 < 0)) {
          piVar3 = __errno_location();
          local_f8[0] = *piVar3;
        }
        else {
          getsockopt(*(int *)(param_1 + 0x10),1,4,local_f8,(socklen_t *)(local_f8 + 1));
        }
      }
      if ((DAT_001231c0 & 2) != 0) {
        piVar3 = __errno_location();
        pcVar4 = strerror(*piVar3);
        piVar3 = __errno_location();
        g_log("Slirp",0x80," --- soread() disconnected, nn = %d, errno = %d-%s",local_f8[3],*piVar3,
              pcVar4);
      }
      FUN_00115bd5(param_1);
      if ((((local_f8[0] == 0x68) || (local_f8[0] == 0x6f)) || (local_f8[0] == 0x6b)) ||
         (local_f8[0] == 0x20)) {
        FUN_0010e65c(*(undefined8 *)(param_1 + 0x150),local_f8[0]);
      }
      else {
        FUN_0010e8bc(*(undefined8 *)(param_1 + 0x150));
      }
      iVar1 = -1;
    }
  }
  else {
    if ((local_fc == 2) && ((long)local_f8[3] == local_c0)) {
      sVar2 = recv(*(int *)(param_1 + 0x10),local_b8,local_b0,0);
      local_e8 = (int)sVar2;
      if (0 < local_e8) {
        local_f8[3] = local_f8[3] + local_e8;
      }
    }
    if ((DAT_001231c0 & 2) != 0) {
      g_log("Slirp",0x80," ... read nn = %d bytes",local_f8[3]);
    }
    *local_e0 = *local_e0 + local_f8[3];
    *(long *)(local_e0 + 2) = *(long *)(local_e0 + 2) + (long)local_f8[3];
    iVar1 = local_f8[3];
    if ((ulong)(uint)local_e0[1] + *(long *)(local_e0 + 6) <= *(ulong *)(local_e0 + 2)) {
      *(ulong *)(local_e0 + 2) = *(long *)(local_e0 + 2) - (ulong)(uint)local_e0[1];
    }
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar1;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



int FUN_00114126(long param_1,void *param_2,int param_3)

{
  ulong uVar1;
  long in_FS_OFFSET;
  undefined local_4c [4];
  int local_48;
  int local_44;
  int *local_40;
  void *local_38;
  ulong local_30;
  void *local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_40 = (int *)(param_1 + 0x188);
  local_48 = param_3;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"soreadbuf...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if (param_3 < 1) {
                    // WARNING: Subroutine does not return
    __assert_fail("size > 0",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.c"
                  ,0x104,"soreadbuf");
  }
  uVar1 = FUN_0011398c(param_1,&local_38,local_4c);
  if (uVar1 < (ulong)(long)param_3) {
    FUN_00115bd5(param_1);
    FUN_0010e8bc(*(undefined8 *)(param_1 + 0x150));
    g_log("Slirp",8,"soreadbuf buffer too small");
    param_3 = -1;
  }
  else {
    if ((ulong)(long)local_48 <= local_30) {
      local_30 = (long)local_48;
    }
    local_44 = (int)local_30;
    memcpy(local_38,param_2,(long)local_44);
    local_48 = local_48 - local_44;
    if (local_48 != 0) {
      memcpy(local_28,(void *)((long)param_2 + (long)local_44),(long)local_48);
    }
    *local_40 = *local_40 + param_3;
    *(long *)(local_40 + 2) = *(long *)(local_40 + 2) + (long)param_3;
    if ((ulong)(uint)local_40[1] + *(long *)(local_40 + 6) <= *(ulong *)(local_40 + 2)) {
      *(ulong *)(local_40 + 2) = *(long *)(local_40 + 2) - (ulong)(uint)local_40[1];
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return param_3;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



int FUN_0011432e(long param_1)

{
  long lVar1;
  int iVar2;
  
  lVar1 = *(long *)(param_1 + 0x150);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"sorecvoob...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  iVar2 = FUN_00113d10(param_1);
  if (0 < iVar2) {
    *(int *)(lVar1 + 0x80) = *(int *)(lVar1 + 0x78) + *(int *)(param_1 + 0x188);
    *(undefined *)(lVar1 + 0x22) = 1;
    FUN_00105b44(lVar1);
    *(undefined *)(lVar1 + 0x22) = 0;
  }
  return iVar2;
}



int FUN_001143fb(long param_1)

{
  uint uVar1;
  int *piVar2;
  long in_FS_OFFSET;
  uint local_82c;
  uint local_828;
  undefined local_818 [2056];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  piVar2 = (int *)(param_1 + 0x168);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"sosendoob...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," sb->sb_cc = %d",*piVar2);
  }
  if (0x800 < *(uint *)(param_1 + 0x40)) {
    *(undefined4 *)(param_1 + 0x40) = 0x800;
  }
  if (*(ulong *)(param_1 + 0x178) < *(ulong *)(param_1 + 0x170)) {
    local_82c = FUN_001053ed(param_1,*(undefined8 *)(param_1 + 0x178),
                             *(undefined4 *)(param_1 + 0x40),1);
  }
  else {
    uVar1 = *(uint *)(param_1 + 0x40);
    local_828 = ((int)*(undefined8 *)(param_1 + 0x180) + *(int *)(param_1 + 0x16c)) -
                (int)*(undefined8 *)(param_1 + 0x178);
    if (uVar1 < local_828) {
      local_828 = uVar1;
    }
    memcpy(local_818,*(void **)(param_1 + 0x178),(long)(int)local_828);
    uVar1 = uVar1 - local_828;
    if (uVar1 != 0) {
      local_82c = (int)*(undefined8 *)(param_1 + 0x170) - (int)*(undefined8 *)(param_1 + 0x180);
      if (uVar1 < local_82c) {
        local_82c = uVar1;
      }
      memcpy(local_818 + (int)local_828,*(void **)(param_1 + 0x180),(long)(int)local_82c);
      local_828 = local_828 + local_82c;
    }
    local_82c = FUN_001053ed(param_1,local_818,(long)(int)local_828,1);
  }
  if (-1 < (int)local_82c) {
    *(uint *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) - local_82c;
    if ((DAT_001231c0 & 2) != 0) {
      g_log("Slirp",0x80," ---2 sent %d bytes urgent data, %d urgent bytes left",local_82c,
            *(undefined4 *)(param_1 + 0x40));
    }
    *piVar2 = *piVar2 - local_82c;
    *(long *)(param_1 + 0x178) = *(long *)(param_1 + 0x178) + (long)(int)local_82c;
    if ((ulong)*(uint *)(param_1 + 0x16c) + *(long *)(param_1 + 0x180) <=
        *(ulong *)(param_1 + 0x178)) {
      *(ulong *)(param_1 + 0x178) = *(long *)(param_1 + 0x178) - (ulong)*(uint *)(param_1 + 0x16c);
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return local_82c;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



int FUN_00114789(long param_1)

{
  uint uVar1;
  long lVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  long in_FS_OFFSET;
  int local_54;
  int local_50;
  ulong local_30;
  undefined8 local_28;
  ulong local_20;
  
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  piVar5 = (int *)(param_1 + 0x168);
  iVar4 = *piVar5;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"sowrite...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if (*(int *)(param_1 + 0x40) == 0) {
LAB_00114858:
    local_28 = 0;
    local_20 = 0;
    if (*(ulong *)(param_1 + 0x178) < *(ulong *)(param_1 + 0x170)) {
      local_30 = *(long *)(param_1 + 0x170) - *(long *)(param_1 + 0x178);
      if ((ulong)(long)iVar4 < local_30) {
        local_30 = (ulong)iVar4;
      }
      local_54 = 1;
    }
    else {
      local_30 = (*(long *)(param_1 + 0x180) + (ulong)*(uint *)(param_1 + 0x16c)) -
                 *(long *)(param_1 + 0x178);
      if ((ulong)(long)iVar4 < local_30) {
        local_30 = (ulong)iVar4;
      }
      iVar4 = iVar4 - (int)local_30;
      if (iVar4 == 0) {
        local_54 = 1;
      }
      else {
        local_28 = *(undefined8 *)(param_1 + 0x180);
        local_20 = *(long *)(param_1 + 0x170) - *(long *)(param_1 + 0x180);
        if ((ulong)(long)iVar4 < local_20) {
          local_20 = (ulong)iVar4;
        }
        local_54 = 2;
      }
    }
    local_50 = FUN_001053ed(param_1,*(undefined8 *)(param_1 + 0x178),local_30,0);
    if ((local_50 < 0) &&
       ((piVar6 = __errno_location(), *piVar6 == 0xb || (piVar6 = __errno_location(), *piVar6 == 4))
       )) {
      local_50 = 0;
      goto LAB_00114b19;
    }
    if (0 < local_50) {
      if (((local_54 == 2) && ((long)local_50 == local_30)) &&
         (iVar4 = FUN_001053ed(param_1,local_28,local_20,0), 0 < iVar4)) {
        local_50 = local_50 + iVar4;
      }
      if ((DAT_001231c0 & 2) != 0) {
        g_log("Slirp",0x80,"  ... wrote nn = %d bytes",local_50);
      }
      *piVar5 = *piVar5 - local_50;
      *(long *)(param_1 + 0x178) = *(long *)(param_1 + 0x178) + (long)local_50;
      if ((ulong)*(uint *)(param_1 + 0x16c) + *(long *)(param_1 + 0x180) <=
          *(ulong *)(param_1 + 0x178)) {
        *(ulong *)(param_1 + 0x178) = *(long *)(param_1 + 0x178) - (ulong)*(uint *)(param_1 + 0x16c)
        ;
      }
      if (((*(uint *)(param_1 + 0x14c) & 0x40) != 0) && (*piVar5 == 0)) {
        FUN_00115c85(param_1);
      }
      goto LAB_00114b19;
    }
  }
  else {
    uVar1 = *(uint *)(param_1 + 0x40);
    uVar3 = FUN_001143fb(param_1);
    if (uVar1 <= uVar3) {
      if (*piVar5 == 0) {
        local_50 = 0;
        goto LAB_00114b19;
      }
      goto LAB_00114858;
    }
  }
  if ((DAT_001231c0 & 2) != 0) {
    piVar5 = __errno_location();
    g_log("Slirp",0x80," --- sowrite disconnected, so->so_state = %x, errno = %d",
          *(undefined4 *)(param_1 + 0x14c),*piVar5);
  }
  FUN_00115c85(param_1);
  FUN_0010e8bc(*(undefined8 *)(param_1 + 0x150));
  local_50 = -1;
LAB_00114b19:
  if (lVar2 == *(long *)(in_FS_OFFSET + 0x28)) {
    return local_50;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00114b2f(long param_1)

{
  uint16_t uVar1;
  uint16_t uVar2;
  int iVar3;
  ssize_t sVar4;
  int *piVar5;
  char *pcVar6;
  long in_FS_OFFSET;
  undefined local_2c2;
  undefined local_2c1;
  socklen_t local_2c0;
  int local_2bc;
  int local_2b8;
  int local_2b4;
  long local_2b0;
  sockaddr local_2a8;
  undefined8 local_298;
  undefined8 local_290;
  undefined8 local_288;
  undefined8 local_280;
  undefined8 local_278;
  undefined8 local_270;
  undefined8 local_268;
  undefined8 local_260;
  undefined8 local_258;
  undefined8 local_250;
  undefined8 local_248;
  undefined8 local_240;
  undefined8 local_238;
  undefined8 local_230;
  sockaddr local_228;
  undefined8 local_218;
  undefined8 local_210;
  undefined8 local_208;
  undefined8 local_200;
  undefined8 local_1f8;
  undefined8 local_1f0;
  undefined8 local_1e8;
  undefined8 local_1e0;
  undefined8 local_1d8;
  undefined8 local_1d0;
  undefined8 local_1c8;
  undefined8 local_1c0;
  undefined8 local_1b8;
  undefined8 local_1b0;
  undefined8 local_1a8;
  undefined8 local_1a0;
  undefined8 local_198;
  undefined8 local_190;
  undefined8 local_188;
  undefined8 local_180;
  undefined8 local_178;
  undefined8 local_170;
  undefined8 local_168;
  undefined8 local_160;
  undefined8 local_158;
  undefined8 local_150;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined8 local_130;
  undefined local_128 [264];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_2c0 = 0x80;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"sorecvfrom...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if (*(char *)(param_1 + 0x14a) == '\x01') {
    sVar4 = recvfrom(*(int *)(param_1 + 0x10),local_128,0x100,0,&local_2a8,&local_2c0);
    local_2b4 = (int)sVar4;
    if ((local_2b4 == -1) || (local_2b4 == 0)) {
      local_2c2 = 3;
      piVar5 = __errno_location();
      if (*piVar5 == 0x71) {
        local_2c2 = 1;
      }
      else {
        piVar5 = __errno_location();
        if (*piVar5 == 0x65) {
          local_2c2 = 0;
        }
      }
      if ((DAT_001231c0 & 2) != 0) {
        piVar5 = __errno_location();
        pcVar6 = strerror(*piVar5);
        piVar5 = __errno_location();
        g_log("Slirp",0x80," udp icmp rx errno = %d-%s",*piVar5,pcVar6);
      }
      piVar5 = __errno_location();
      pcVar6 = strerror(*piVar5);
      FUN_00117ef4(*(undefined8 *)(param_1 + 0x30),3,local_2c2,0,pcVar6);
    }
    else {
      FUN_001182f3(*(undefined8 *)(param_1 + 0x30));
      *(undefined8 *)(param_1 + 0x30) = 0;
    }
    FUN_0010a15c(param_1);
  }
  else {
    iVar3 = ioctl(*(int *)(param_1 + 0x10),0x541b,&local_2bc);
    if (iVar3 == 0) {
      if ((local_2bc != 0) &&
         (local_2b0 = FUN_00110cac(*(undefined8 *)(param_1 + 0x28)), local_2b0 != 0)) {
        if (*(short *)(param_1 + 0x48) == 2) {
          *(long *)(local_2b0 + 0x30) = *(long *)(local_2b0 + 0x30) + 0x2c;
        }
        else if (*(short *)(param_1 + 0x48) == 10) {
          *(long *)(local_2b0 + 0x30) = *(long *)(local_2b0 + 0x30) + 0x40;
        }
        else {
          g_assertion_message_expr
                    ("Slirp",
                     "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.c"
                     ,0x22a,"sorecvfrom",0);
        }
        if ((*(uint *)(local_2b0 + 0x20) & 1) == 0) {
          local_2b8 = ((int)local_2b0 + 0x60 + *(int *)(local_2b0 + 0x24)) -
                      (int)*(undefined8 *)(local_2b0 + 0x30);
        }
        else {
          local_2b8 = ((int)*(undefined8 *)(local_2b0 + 0x58) + *(int *)(local_2b0 + 0x24)) -
                      (int)*(undefined8 *)(local_2b0 + 0x30);
        }
        local_2b8 = local_2b8 - *(int *)(local_2b0 + 0x38);
        if (local_2b8 < local_2bc) {
          local_2bc = local_2bc +
                      ((int)*(undefined8 *)(local_2b0 + 0x30) - ((int)local_2b0 + 0x60)) +
                      *(int *)(local_2b0 + 0x38) + 1;
          FUN_00111017(local_2b0,local_2bc);
          if ((*(uint *)(local_2b0 + 0x20) & 1) == 0) {
            local_2b8 = ((int)local_2b0 + 0x60 + *(int *)(local_2b0 + 0x24)) -
                        (int)*(undefined8 *)(local_2b0 + 0x30);
          }
          else {
            local_2b8 = ((int)*(undefined8 *)(local_2b0 + 0x58) + *(int *)(local_2b0 + 0x24)) -
                        (int)*(undefined8 *)(local_2b0 + 0x30);
          }
          local_2b8 = local_2b8 - *(int *)(local_2b0 + 0x38);
        }
        sVar4 = recvfrom(*(int *)(param_1 + 0x10),*(void **)(local_2b0 + 0x30),(long)local_2b8,0,
                         &local_2a8,&local_2c0);
        *(int *)(local_2b0 + 0x38) = (int)sVar4;
        if ((DAT_001231c0 & 2) != 0) {
          piVar5 = __errno_location();
          pcVar6 = strerror(*piVar5);
          piVar5 = __errno_location();
          g_log("Slirp",0x80," did recvfrom %d, errno = %d-%s",*(undefined4 *)(local_2b0 + 0x38),
                *piVar5,pcVar6);
        }
        if (*(int *)(local_2b0 + 0x38) < 0) {
          if (*(short *)(param_1 + 200) == 2) {
            local_2c1 = 3;
            piVar5 = __errno_location();
            if (*piVar5 == 0x71) {
              local_2c1 = 1;
            }
            else {
              piVar5 = __errno_location();
              if (*piVar5 == 0x65) {
                local_2c1 = 0;
              }
            }
            if ((DAT_001231c0 & 2) != 0) {
              g_log("Slirp",0x80," rx error, tx icmp ICMP_UNREACH:%i",local_2c1);
            }
            piVar5 = __errno_location();
            pcVar6 = strerror(*piVar5);
            FUN_00117ef4(*(undefined8 *)(param_1 + 0x30),3,local_2c1,0,pcVar6);
          }
          else if (*(short *)(param_1 + 200) == 10) {
            local_2c1 = 4;
            piVar5 = __errno_location();
            if (*piVar5 == 0x71) {
              local_2c1 = 3;
            }
            else {
              piVar5 = __errno_location();
              if (*piVar5 == 0x65) {
                local_2c1 = 0;
              }
            }
            if ((DAT_001231c0 & 2) != 0) {
              g_log("Slirp",0x80," rx error, tx icmp6 ICMP_UNREACH:%i",local_2c1);
            }
            FUN_00111956(*(undefined8 *)(param_1 + 0x30),1,local_2c1);
          }
          else {
            g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.c"
                       ,0x25d,"sorecvfrom",0);
          }
          FUN_00110e00(local_2b0);
        }
        else {
          if (*(int *)(param_1 + 0x158) != 0) {
            uVar1 = *(uint16_t *)(param_1 + 0x4a);
            uVar2 = htons(0x35);
            if (uVar1 == uVar2) {
              *(int *)(param_1 + 0x158) = DAT_001231c8 + 10000;
            }
            else {
              *(int *)(param_1 + 0x158) = DAT_001231c8 + 240000;
            }
          }
          local_228.sa_family = local_2a8.sa_family;
          local_228.sa_data[0] = local_2a8.sa_data[0];
          local_228.sa_data[1] = local_2a8.sa_data[1];
          local_228.sa_data[2] = local_2a8.sa_data[2];
          local_228.sa_data[3] = local_2a8.sa_data[3];
          local_228.sa_data[4] = local_2a8.sa_data[4];
          local_228.sa_data[5] = local_2a8.sa_data[5];
          local_228.sa_data[6] = local_2a8.sa_data[6];
          local_228.sa_data[7] = local_2a8.sa_data[7];
          local_228.sa_data[8] = local_2a8.sa_data[8];
          local_228.sa_data[9] = local_2a8.sa_data[9];
          local_228.sa_data[10] = local_2a8.sa_data[10];
          local_228.sa_data[0xb] = local_2a8.sa_data[0xb];
          local_228.sa_data[0xc] = local_2a8.sa_data[0xc];
          local_228.sa_data[0xd] = local_2a8.sa_data[0xd];
          local_218 = local_298;
          local_210 = local_290;
          local_208 = local_288;
          local_200 = local_280;
          local_1f8 = local_278;
          local_1f0 = local_270;
          local_1e8 = local_268;
          local_1e0 = local_260;
          local_1d8 = local_258;
          local_1d0 = local_250;
          local_1c8 = local_248;
          local_1c0 = local_240;
          local_1b8 = local_238;
          local_1b0 = local_230;
          FUN_0011602d(param_1,&local_228);
          local_1a8 = *(undefined8 *)(param_1 + 200);
          local_1a0 = *(undefined8 *)(param_1 + 0xd0);
          local_198 = *(undefined8 *)(param_1 + 0xd8);
          local_190 = *(undefined8 *)(param_1 + 0xe0);
          local_188 = *(undefined8 *)(param_1 + 0xe8);
          local_180 = *(undefined8 *)(param_1 + 0xf0);
          local_178 = *(undefined8 *)(param_1 + 0xf8);
          local_170 = *(undefined8 *)(param_1 + 0x100);
          local_168 = *(undefined8 *)(param_1 + 0x108);
          local_160 = *(undefined8 *)(param_1 + 0x110);
          local_158 = *(undefined8 *)(param_1 + 0x118);
          local_150 = *(undefined8 *)(param_1 + 0x120);
          local_148 = *(undefined8 *)(param_1 + 0x128);
          local_140 = *(undefined8 *)(param_1 + 0x130);
          local_130 = *(undefined8 *)(param_1 + 0x140);
          local_138 = *(undefined8 *)(param_1 + 0x138);
          if (*(short *)(param_1 + 0x48) == 2) {
            FUN_00109e86(param_1,local_2b0,&local_228,&local_1a8,*(undefined *)(param_1 + 0x148));
          }
          else if (*(short *)(param_1 + 0x48) == 10) {
            FUN_0011b588(param_1,local_2b0,&local_228,&local_1a8);
          }
          else {
            g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.c"
                       ,0x280,"sorecvfrom",0);
          }
        }
      }
    }
    else if ((DAT_001231c0 & 2) != 0) {
      piVar5 = __errno_location();
      pcVar6 = strerror(*piVar5);
      piVar5 = __errno_location();
      g_log("Slirp",0x80," ioctlsocket errno = %d-%s\n",*piVar5,pcVar6);
    }
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined8 FUN_001154c3(long param_1,long param_2)

{
  int iVar1;
  socklen_t __addr_len;
  undefined8 uVar2;
  ssize_t sVar3;
  long in_FS_OFFSET;
  sockaddr local_a8;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"sosendto...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_2);
  }
  local_a8._0_8_ = *(undefined8 *)(param_1 + 0x48);
  local_a8.sa_data._6_8_ = *(undefined8 *)(param_1 + 0x50);
  local_98 = *(undefined8 *)(param_1 + 0x58);
  local_90 = *(undefined8 *)(param_1 + 0x60);
  local_88 = *(undefined8 *)(param_1 + 0x68);
  local_80 = *(undefined8 *)(param_1 + 0x70);
  local_78 = *(undefined8 *)(param_1 + 0x78);
  local_70 = *(undefined8 *)(param_1 + 0x80);
  local_68 = *(undefined8 *)(param_1 + 0x88);
  local_60 = *(undefined8 *)(param_1 + 0x90);
  local_58 = *(undefined8 *)(param_1 + 0x98);
  local_50 = *(undefined8 *)(param_1 + 0xa0);
  local_48 = *(undefined8 *)(param_1 + 0xa8);
  local_40 = *(undefined8 *)(param_1 + 0xb0);
  local_30 = *(undefined8 *)(param_1 + 0xc0);
  local_38 = *(undefined8 *)(param_1 + 0xb8);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," sendto()ing)...");
  }
  iVar1 = FUN_00115f9c(param_1,&local_a8);
  if (iVar1 < 0) {
    uVar2 = 0xffffffff;
  }
  else {
    __addr_len = FUN_00113625(&local_a8);
    sVar3 = sendto(*(int *)(param_1 + 0x10),*(void **)(param_2 + 0x30),
                   (long)*(int *)(param_2 + 0x38),0,&local_a8,__addr_len);
    if ((int)sVar3 < 0) {
      uVar2 = 0xffffffff;
    }
    else {
      if (*(int *)(param_1 + 0x158) != 0) {
        *(int *)(param_1 + 0x158) = DAT_001231c8 + 240000;
      }
      *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) & 0xf000;
      *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 4;
      uVar2 = 0;
    }
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar2;
}



long FUN_00115770(long param_1,in_addr param_2,uint16_t param_3,in_addr param_4,uint16_t param_5,
                 uint param_6)

{
  uint16_t uVar1;
  int iVar2;
  char *pcVar3;
  undefined8 uVar4;
  int *piVar5;
  long lVar6;
  long in_FS_OFFSET;
  undefined4 local_40;
  socklen_t local_3c;
  int local_38;
  int local_34;
  long local_30;
  sockaddr local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_40 = 1;
  local_3c = 0x10;
  memset(&local_28,0,0x10);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"tcp_listen...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    pcVar3 = inet_ntoa(param_2);
    g_log("Slirp",0x80," haddr = %s",pcVar3);
  }
  if ((DAT_001231c0 & 1) != 0) {
    uVar1 = ntohs(param_3);
    g_log("Slirp",0x80," hport = %d",uVar1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    pcVar3 = inet_ntoa(param_4);
    g_log("Slirp",0x80," laddr = %s",pcVar3);
  }
  if ((DAT_001231c0 & 1) != 0) {
    uVar1 = ntohs(param_5);
    g_log("Slirp",0x80," lport = %d",uVar1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," flags = %x",param_6);
  }
  local_30 = FUN_0011376d(param_1);
  uVar4 = FUN_0010e571(local_30);
  *(undefined8 *)(local_30 + 0x150) = uVar4;
  if (*(long *)(local_30 + 0x150) == 0) {
    g_free(local_30);
    lVar6 = 0;
  }
  else {
    FUN_00106a33(local_30,param_1 + 0x1c0);
    if ((param_6 & 0x200) != 0) {
      *(undefined2 *)(*(long *)(local_30 + 0x150) + 0x16) = 300;
    }
    *(uint *)(local_30 + 0x14c) = *(uint *)(local_30 + 0x14c) & 0xf000;
    *(uint *)(local_30 + 0x14c) = param_6 | 0x100 | *(uint *)(local_30 + 0x14c);
    *(undefined2 *)(local_30 + 200) = 2;
    *(uint16_t *)(local_30 + 0xca) = param_5;
    *(in_addr_t *)(local_30 + 0xcc) = param_4.s_addr;
    local_28.sa_family = 2;
    local_28.sa_data._0_2_ = param_3;
    local_28.sa_data._2_4_ = param_2.s_addr;
    local_38 = FUN_001081c9(2,1,0);
    if (-1 < local_38) {
      iVar2 = FUN_001133cd(local_38);
      if (-1 < iVar2) {
        iVar2 = bind(local_38,&local_28,0x10);
        if (-1 < iVar2) {
          iVar2 = listen(local_38,1);
          if (-1 < iVar2) {
            setsockopt(local_38,1,10,&local_40,4);
            local_40 = 1;
            setsockopt(local_38,6,1,&local_40,4);
            getsockname(local_38,&local_28,&local_3c);
            *(undefined2 *)(local_30 + 0x48) = 2;
            *(undefined2 *)(local_30 + 0x4a) = local_28.sa_data._0_2_;
            if ((local_28.sa_data._2_4_ == 0) || (local_28.sa_data._2_4_ == DAT_001231c4)) {
              *(undefined4 *)(local_30 + 0x4c) = *(undefined4 *)(param_1 + 0x14);
            }
            else {
              *(undefined4 *)(local_30 + 0x4c) = local_28.sa_data._2_4_;
            }
            *(int *)(local_30 + 0x10) = local_38;
            lVar6 = local_30;
            goto LAB_00115b3d;
          }
        }
      }
    }
    piVar5 = __errno_location();
    local_34 = *piVar5;
    if (-1 < local_38) {
      close(local_38);
    }
    FUN_0011385c(local_30);
    piVar5 = __errno_location();
    *piVar5 = local_34;
    lVar6 = 0;
  }
LAB_00115b3d:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return lVar6;
}



void FUN_00115b53(long param_1)

{
  *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) & 0xffffffa2;
  *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 2;
  return;
}



void FUN_00115b94(long param_1)

{
  *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) & 0xffffffbc;
  *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 4;
  return;
}



void FUN_00115bd5(long param_1)

{
  if ((*(uint *)(param_1 + 0x14c) & 1) == 0) {
    shutdown(*(int *)(param_1 + 0x10),0);
  }
  *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) & 0xfffffffd;
  if ((*(uint *)(param_1 + 0x14c) & 0x10) == 0) {
    *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 8;
  }
  else {
    *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) & 0xf000;
    *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 1;
  }
  return;
}



void FUN_00115c85(long param_1)

{
  if ((*(uint *)(param_1 + 0x14c) & 1) == 0) {
    shutdown(*(int *)(param_1 + 0x10),1);
  }
  *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) & 0xfffffffd;
  if ((*(uint *)(param_1 + 0x14c) & 8) == 0) {
    *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 0x10;
  }
  else {
    *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) & 0xf000;
    *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 1;
  }
  return;
}



void FUN_00115d35(long param_1)

{
  if (*(int *)(param_1 + 0x168) == 0) {
    FUN_00115c85(param_1);
  }
  else {
    *(uint *)(param_1 + 0x14c) = *(uint *)(param_1 + 0x14c) | 0x40;
  }
  return;
}



undefined4 FUN_00115d7d(long param_1,long param_2,long param_3)

{
  uint16_t uVar1;
  uint16_t uVar2;
  int iVar3;
  undefined4 uVar4;
  
  if ((*(char *)(param_1 + 0x1788) == '\x01') ||
     (*(int *)(param_2 + 0x4c) != *(int *)(param_1 + 0x40))) {
    if ((*(int *)(param_2 + 0x4c) == *(int *)(param_1 + 0x14)) || (*(int *)(param_2 + 0x4c) == -1))
    {
      if (*(char *)(param_1 + 0x90) != '\0') {
        return 0;
      }
      *(undefined4 *)(param_3 + 4) = DAT_001231c4;
    }
    uVar4 = 1;
  }
  else {
    uVar1 = *(uint16_t *)(param_2 + 0x4a);
    uVar2 = htons(0x35);
    if ((uVar1 == uVar2) && (iVar3 = FUN_001031dd(param_3 + 4), -1 < iVar3)) {
      uVar4 = 1;
    }
    else {
      uVar4 = 0;
    }
  }
  return uVar4;
}



undefined8 FUN_00115e43(long param_1,long param_2,long param_3)

{
  uint16_t uVar1;
  char cVar2;
  uint16_t uVar3;
  int iVar4;
  undefined8 uVar5;
  long in_FS_OFFSET;
  undefined4 local_3c;
  undefined8 local_38;
  undefined8 local_30;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (*(char *)(param_1 + 0x1788) != '\x01') {
    cVar2 = FUN_00113425(param_2 + 0x50,param_1 + 0x44);
    if (cVar2 != '\0') {
      uVar1 = *(uint16_t *)(param_2 + 0x4a);
      uVar3 = htons(0x35);
      if (uVar1 == uVar3) {
        iVar4 = FUN_00103257(param_3 + 8,&local_3c);
        if (-1 < iVar4) {
          *(undefined4 *)(param_3 + 0x18) = local_3c;
          uVar5 = 1;
          goto LAB_00115f81;
        }
      }
      uVar5 = 0;
      goto LAB_00115f81;
    }
  }
  cVar2 = FUN_00113454(param_2 + 0x50,param_1 + 0x18,*(undefined *)(param_1 + 0x28));
  if (cVar2 == '\0') {
    local_38 = 0x2ff;
    local_30 = 0x100000000000000;
    cVar2 = FUN_00113425(param_2 + 0x50,&local_38);
    if (cVar2 != '\0') goto LAB_00115f4c;
  }
  else {
LAB_00115f4c:
    if (*(char *)(param_1 + 0x90) != '\0') {
      uVar5 = 0;
      goto LAB_00115f81;
    }
    *(undefined8 *)(param_3 + 8) = 0;
    *(undefined8 *)(param_3 + 0x10) = 0;
  }
  uVar5 = 1;
LAB_00115f81:
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar5;
}



undefined8 FUN_00115f9c(long param_1,short *param_2)

{
  int *piVar1;
  undefined8 uVar2;
  undefined local_9;
  
  local_9 = '\x01';
  if (*param_2 == 2) {
    local_9 = FUN_00115d7d(*(undefined8 *)(param_1 + 0x28),param_1,param_2);
  }
  else if (*param_2 == 10) {
    local_9 = FUN_00115e43(*(undefined8 *)(param_1 + 0x28),param_1,param_2);
  }
  if (local_9 == '\x01') {
    uVar2 = 0;
  }
  else {
    piVar1 = __errno_location();
    *piVar1 = 1;
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



void FUN_0011602d(long param_1,short *param_2)

{
  long lVar1;
  undefined8 uVar2;
  char cVar3;
  
  lVar1 = *(long *)(param_1 + 0x28);
  if (*param_2 == 2) {
    if ((*(uint *)(param_1 + 0x4c) & *(uint *)(lVar1 + 0x10)) == *(uint *)(lVar1 + 0xc)) {
      if (~*(uint *)(lVar1 + 0x10) == (*(uint *)(param_1 + 0x4c) & ~*(uint *)(lVar1 + 0x10))) {
        *(undefined4 *)(param_2 + 2) = *(undefined4 *)(lVar1 + 0x14);
      }
      else if ((*(int *)(param_2 + 2) == DAT_001231c4) ||
              (*(int *)(param_1 + 0x4c) != *(int *)(lVar1 + 0x14))) {
        *(undefined4 *)(param_2 + 2) = *(undefined4 *)(param_1 + 0x4c);
      }
    }
  }
  else if (((*param_2 == 10) &&
           (cVar3 = FUN_00113454(param_1 + 0x50,lVar1 + 0x18,*(undefined *)(lVar1 + 0x28)),
           cVar3 != '\0')) &&
          ((cVar3 = FUN_00113425(param_2 + 4,&in6addr_loopback), cVar3 != '\0' ||
           (cVar3 = FUN_00113425(param_1 + 0x50,lVar1 + 0x2c), cVar3 != '\x01')))) {
    uVar2 = *(undefined8 *)(param_1 + 0x58);
    *(undefined8 *)(param_2 + 4) = *(undefined8 *)(param_1 + 0x50);
    *(undefined8 *)(param_2 + 8) = uVar2;
  }
  return;
}



void FUN_00116188(long param_1)

{
  long lVar1;
  undefined8 uVar2;
  char cVar3;
  
  lVar1 = *(long *)(param_1 + 0x28);
  if (*(short *)(param_1 + 0x48) == 2) {
    if ((*(int *)(param_1 + 0x4c) == 0) ||
       ((DAT_001231b8 & (DAT_001231c4 ^ *(uint *)(param_1 + 0x4c))) == 0)) {
      *(undefined4 *)(param_1 + 0x4c) = *(undefined4 *)(lVar1 + 0x14);
    }
  }
  else if ((*(short *)(param_1 + 0x48) == 10) &&
          ((cVar3 = FUN_00113425(param_1 + 0x50,in6addr_any), cVar3 != '\0' ||
           (cVar3 = FUN_00113425(param_1 + 0x50,&in6addr_loopback), cVar3 != '\0')))) {
    uVar2 = *(undefined8 *)(lVar1 + 0x34);
    *(undefined8 *)(param_1 + 0x50) = *(undefined8 *)(lVar1 + 0x2c);
    *(undefined8 *)(param_1 + 0x58) = uVar2;
  }
  return;
}



void FUN_00116250(long param_1,int param_2)

{
  char cVar1;
  
  cVar1 = FUN_001085b0(param_1 + 0x188,(long)param_2);
  if (cVar1 != '\0') {
    (**(code **)(*(long *)(*(long *)(param_1 + 0x28) + 0x1768) + 0x40))
              (*(undefined8 *)(*(long *)(param_1 + 0x28) + 6000));
  }
  return;
}



void FUN_001162ac(long param_1)

{
  *(long *)(param_1 + 0x100) = param_1 + 0xf8;
  *(undefined8 *)(param_1 + 0xf8) = *(undefined8 *)(param_1 + 0x100);
  FUN_001097ea(param_1);
  FUN_0010dbc9(param_1);
  FUN_001175b6(param_1);
  return;
}



void FUN_0011630f(undefined8 param_1)

{
  FUN_0010983b(param_1);
  FUN_0010dc28(param_1);
  FUN_00117607(param_1);
  return;
}



void FUN_00116346(long param_1)

{
  byte bVar1;
  long lVar2;
  byte bVar3;
  uint16_t uVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  undefined8 *puVar8;
  long local_40;
  undefined8 *local_30;
  
  lVar2 = *(long *)(param_1 + 0x40);
  if (*(char *)(lVar2 + 9) == '\x01') {
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80,"ip_input...");
    }
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," m = %p",param_1);
    }
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," m_len = %d",*(undefined4 *)(param_1 + 0x38));
    }
    if ((0x13 < *(uint *)(param_1 + 0x38)) &&
       (pbVar7 = *(byte **)(param_1 + 0x30), (*pbVar7 & 0xf0) == 0x40)) {
      bVar3 = *pbVar7 & 0xf;
      uVar5 = (uint)bVar3 << 2;
      if ((0x13 < uVar5) &&
         (((int)uVar5 <= *(int *)(param_1 + 0x38) &&
          (iVar6 = FUN_0010d634(param_1,(ulong)bVar3 << 2), iVar6 == 0)))) {
        uVar4 = ntohs(*(uint16_t *)(pbVar7 + 2));
        *(uint16_t *)(pbVar7 + 2) = uVar4;
        if (uVar5 <= *(ushort *)(pbVar7 + 2)) {
          uVar4 = ntohs(*(uint16_t *)(pbVar7 + 4));
          *(uint16_t *)(pbVar7 + 4) = uVar4;
          uVar4 = ntohs(*(uint16_t *)(pbVar7 + 6));
          *(uint16_t *)(pbVar7 + 6) = uVar4;
          if ((int)(uint)*(ushort *)(pbVar7 + 2) <= *(int *)(param_1 + 0x38)) {
            if ((int)(uint)*(ushort *)(pbVar7 + 2) < *(int *)(param_1 + 0x38)) {
              FUN_00111173(param_1,(uint)*(ushort *)(pbVar7 + 2) - *(int *)(param_1 + 0x38));
            }
            if (pbVar7[8] != 0) {
              local_40 = param_1;
              if ((*(ushort *)(pbVar7 + 6) & 0xbfff) == 0) {
                *(short *)(pbVar7 + 2) = *(short *)(pbVar7 + 2) - (short)uVar5;
              }
              else {
                for (local_30 = *(undefined8 **)(lVar2 + 0xf8);
                    local_30 != (undefined8 *)(lVar2 + 0xf8); local_30 = (undefined8 *)*local_30) {
                  puVar8 = local_30 + -2;
                  if ((((*(short *)(pbVar7 + 4) == *(short *)((long)local_30 + 0x12)) &&
                       (*(int *)(pbVar7 + 0xc) == *(int *)((long)local_30 + 0x14))) &&
                      (*(int *)(pbVar7 + 0x10) == *(int *)(local_30 + 3))) &&
                     (pbVar7[9] == *(byte *)((long)local_30 + 0x11))) goto LAB_001165ba;
                }
                puVar8 = (undefined8 *)0x0;
LAB_001165ba:
                *(short *)(pbVar7 + 2) = *(short *)(pbVar7 + 2) - (short)uVar5;
                if ((*(ushort *)(pbVar7 + 6) & 0x2000) == 0) {
                  pbVar7[1] = pbVar7[1] & 0xfe;
                }
                else {
                  pbVar7[1] = pbVar7[1] | 1;
                }
                *(short *)(pbVar7 + 6) = *(short *)(pbVar7 + 6) << 3;
                if (((pbVar7[1] & 1) == 0) && (*(short *)(pbVar7 + 6) == 0)) {
                  if (puVar8 != (undefined8 *)0x0) {
                    FUN_00116c47(lVar2,puVar8);
                  }
                }
                else {
                  pbVar7 = (byte *)FUN_001166fc(lVar2,pbVar7,puVar8);
                  if (pbVar7 == (byte *)0x0) {
                    return;
                  }
                  local_40 = FUN_001112b5(lVar2,pbVar7);
                }
              }
              bVar1 = pbVar7[9];
              if (bVar1 == 0x11) {
                FUN_00109896(local_40,(ulong)bVar3 << 2);
                return;
              }
              if (bVar1 < 0x12) {
                if (bVar1 == 1) {
                  FUN_001178d8(local_40,(ulong)bVar3 << 2);
                  return;
                }
                if (bVar1 == 6) {
                  FUN_0010a803(local_40,(ulong)bVar3 << 2,0,2);
                  return;
                }
              }
              FUN_00110e00(local_40);
              return;
            }
            FUN_00117ef4(param_1,0xb,0,0,&DAT_0011e6c4);
          }
        }
      }
    }
  }
  FUN_00110e00(param_1);
  return;
}



byte * FUN_001166fc(long param_1,byte *param_2,long *param_3)

{
  byte bVar1;
  long *plVar2;
  undefined8 *puVar3;
  long lVar4;
  long lVar5;
  byte *pbVar6;
  undefined8 uVar7;
  int iVar8;
  long *plVar9;
  long *local_60;
  uint local_48;
  
  lVar4 = FUN_001112b5(param_1,param_2);
  bVar1 = *param_2;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ip_reass...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," ip = %p",param_2);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," fp = %p",param_3);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",lVar4);
  }
  *(long *)(lVar4 + 0x30) = (long)(int)((uint)(bVar1 & 0xf) * 4) + *(long *)(lVar4 + 0x30);
  *(uint *)(lVar4 + 0x38) = *(int *)(lVar4 + 0x38) + (uint)(bVar1 & 0xf) * -4;
  if (param_3 == (long *)0x0) {
    lVar5 = FUN_00110cac(param_1);
    if (lVar5 == 0) {
LAB_00116c31:
      FUN_00110e00(lVar4);
      return (byte *)0x0;
    }
    plVar9 = *(long **)(lVar5 + 0x30);
    FUN_00106a33(plVar9 + 2,param_1 + 0xf8);
    *(undefined *)(plVar9 + 4) = 0x3c;
    *(byte *)((long)plVar9 + 0x21) = param_2[9];
    *(undefined2 *)((long)plVar9 + 0x22) = *(undefined2 *)(param_2 + 4);
    plVar9[1] = (long)plVar9;
    *plVar9 = plVar9[1];
    *(undefined4 *)((long)plVar9 + 0x24) = *(undefined4 *)(param_2 + 0xc);
    *(undefined4 *)(plVar9 + 5) = *(undefined4 *)(param_2 + 0x10);
    local_60 = plVar9;
  }
  else {
    for (plVar9 = (long *)*param_3;
        (plVar9 != param_3 && (*(ushort *)((long)plVar9 + 0x16) <= *(ushort *)(param_2 + 6)));
        plVar9 = (long *)*plVar9) {
    }
    if (((long *)plVar9[1] != param_3) &&
       (iVar8 = ((uint)*(ushort *)(plVar9[1] + 0x16) + (uint)*(ushort *)(plVar9[1] + 0x12)) -
                (uint)*(ushort *)(param_2 + 6), 0 < iVar8)) {
      if ((int)(uint)*(ushort *)(param_2 + 2) <= iVar8) goto LAB_00116c31;
      uVar7 = FUN_001112b5(param_1,param_2);
      FUN_00111173(uVar7,iVar8);
      *(short *)(param_2 + 6) = (short)iVar8 + *(short *)(param_2 + 6);
      *(short *)(param_2 + 2) = *(short *)(param_2 + 2) - (short)iVar8;
    }
    while( true ) {
      local_60 = param_3;
      if ((plVar9 == param_3) ||
         ((uint)*(ushort *)(param_2 + 6) + (uint)*(ushort *)(param_2 + 2) <=
          (uint)*(ushort *)((long)plVar9 + 0x16))) goto LAB_00116a79;
      iVar8 = ((uint)*(ushort *)(param_2 + 6) + (uint)*(ushort *)(param_2 + 2)) -
              (uint)*(ushort *)((long)plVar9 + 0x16);
      if (iVar8 < (int)(uint)*(ushort *)((long)plVar9 + 0x12)) break;
      plVar2 = (long *)*plVar9;
      FUN_00116d4e(plVar9);
      uVar7 = FUN_001112b5(param_1,plVar9);
      FUN_00110e00(uVar7);
      plVar9 = plVar2;
    }
    *(short *)((long)plVar9 + 0x12) = *(short *)((long)plVar9 + 0x12) - (short)iVar8;
    *(short *)((long)plVar9 + 0x16) = *(short *)((long)plVar9 + 0x16) + (short)iVar8;
    uVar7 = FUN_001112b5(param_1,plVar9);
    FUN_00111173(uVar7,iVar8);
  }
LAB_00116a79:
  FUN_00116cca(param_2 + -0x10,plVar9[1]);
  local_48 = 0;
  plVar9 = (long *)*local_60;
  while( true ) {
    if (plVar9 == local_60) {
      if ((*(byte *)(plVar9[1] + 0x11) & 1) == 0) {
        puVar3 = (undefined8 *)*local_60;
        lVar4 = FUN_001112b5(param_1,puVar3);
        if ((*(uint *)(lVar4 + 0x20) & 1) == 0) {
          iVar8 = (int)lVar4 + 0x60;
        }
        else {
          iVar8 = (int)*(undefined8 *)(lVar4 + 0x58);
        }
        plVar9 = (long *)*puVar3;
        while (plVar9 != local_60) {
          uVar7 = FUN_001112b5(param_1,plVar9);
          plVar9 = (long *)*plVar9;
          FUN_00110f1b(lVar4,uVar7);
        }
        lVar5 = *local_60;
        if ((*(uint *)(lVar4 + 0x20) & 1) != 0) {
          lVar5 = *(long *)(lVar4 + 0x58) + (long)((int)puVar3 - iVar8);
        }
        pbVar6 = (byte *)(lVar5 + 0x10);
        *(short *)(lVar5 + 0x12) = (short)local_48;
        *(byte *)(lVar5 + 0x11) = *(byte *)(lVar5 + 0x11) & 0xfe;
        *(undefined4 *)(lVar5 + 0x1c) = *(undefined4 *)((long)local_60 + 0x24);
        *(undefined4 *)(lVar5 + 0x20) = *(undefined4 *)(local_60 + 5);
        FUN_00106a6a(local_60 + 2);
        uVar7 = FUN_001112b5(param_1,local_60);
        FUN_00110e00(uVar7);
        *(uint *)(lVar4 + 0x38) = (uint)(*pbVar6 & 0xf) * 4 + *(int *)(lVar4 + 0x38);
        *(long *)(lVar4 + 0x30) = *(long *)(lVar4 + 0x30) - (long)(int)((uint)(*pbVar6 & 0xf) << 2);
      }
      else {
        pbVar6 = (byte *)0x0;
      }
      return pbVar6;
    }
    if (local_48 != *(ushort *)((long)plVar9 + 0x16)) break;
    local_48 = local_48 + *(ushort *)((long)plVar9 + 0x12);
    plVar9 = (long *)*plVar9;
  }
  return (byte *)0x0;
}



void FUN_00116c47(undefined8 param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  undefined8 *puVar3;
  
  puVar3 = (undefined8 *)*param_2;
  while (puVar3 != param_2) {
    puVar1 = (undefined8 *)*puVar3;
    FUN_00116d4e(puVar3);
    uVar2 = FUN_001112b5(param_1,puVar3);
    FUN_00110e00(uVar2);
    puVar3 = puVar1;
  }
  FUN_00106a6a(param_2 + 2);
  uVar2 = FUN_001112b5(param_1,param_2);
  FUN_00110e00(uVar2);
  return;
}



void FUN_00116cca(long *param_1,long *param_2)

{
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ip_enq...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," prev = %p",param_2);
  }
  param_1[1] = (long)param_2;
  *param_1 = *param_2;
  *(long **)(*param_2 + 8) = param_1;
  *param_2 = (long)param_1;
  return;
}



void FUN_00116d4e(long *param_1)

{
  *(long *)param_1[1] = *param_1;
  *(long *)(*param_1 + 8) = param_1[1];
  return;
}



void FUN_00116d71(long param_1)

{
  char *pcVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *local_20;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ip_slowtimo...");
  }
  local_20 = *(undefined8 **)(param_1 + 0xf8);
  if (local_20 != (undefined8 *)0x0) {
    while (local_20 != (undefined8 *)(param_1 + 0xf8)) {
      puVar3 = local_20 + -2;
      puVar2 = (undefined8 *)*local_20;
      *(char *)(local_20 + 2) = *(char *)(local_20 + 2) + -1;
      pcVar1 = (char *)(local_20 + 2);
      local_20 = puVar2;
      if (*pcVar1 == '\0') {
        FUN_00116c47(param_1,puVar3);
      }
    }
  }
  return;
}



void FUN_00116e28(long param_1)

{
  byte *pbVar1;
  int iVar2;
  
  pbVar1 = *(byte **)(param_1 + 0x30);
  iVar2 = (uint)(*pbVar1 & 0xf) * 4 + -0x14;
  memmove(pbVar1 + 0x14,pbVar1 + 0x14 + iVar2,(ulong)((*(int *)(param_1 + 0x38) - iVar2) - 0x14));
  *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) - iVar2;
  *pbVar1 = *pbVar1 & 0xf0 | 5;
  return;
}



undefined8 FUN_00116eb4(void *param_1,void *param_2)

{
  int iVar1;
  undefined4 extraout_var;
  
  iVar1 = memcmp(param_1,param_2,0x10);
  return CONCAT71((int7)(CONCAT44(extraout_var,iVar1) >> 8),iVar1 == 0);
}



void FUN_00116ee3(long param_1,undefined8 param_2,undefined8 param_3,undefined *param_4)

{
  char cVar1;
  long lVar2;
  long in_FS_OFFSET;
  undefined8 local_88;
  undefined8 local_80;
  undefined *local_78;
  long local_70;
  int local_64;
  long local_60;
  undefined8 local_58;
  undefined8 local_50;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_60 = param_1 + 0x15cc;
  local_88 = param_2;
  local_80 = param_3;
  local_78 = param_4;
  local_70 = param_1;
  inet_ntop(10,&local_88,local_48,0x2e);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ndp_table_add...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," ip = %s",local_48);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," hw addr = %02x:%02x:%02x:%02x:%02x:%02x",*local_78,local_78[1],local_78[2],
          local_78[3],local_78[4],local_78[5]);
  }
  if ((char)local_88 != -1) {
    local_58 = 0;
    local_50 = 0;
    cVar1 = FUN_00116eb4(&local_88,&local_58);
    if (cVar1 == '\0') {
      for (local_64 = 0; local_64 < 0x10; local_64 = local_64 + 1) {
        cVar1 = FUN_00116eb4((long)local_64 * 0x18 + local_60 + 8,&local_88);
        if (cVar1 != '\0') {
          if ((DAT_001231c0 & 1) != 0) {
            g_log("Slirp",0x80," already in table: update the entry...");
          }
          memcpy((void *)((long)local_64 * 0x18 + local_60),local_78,6);
          goto LAB_001171f8;
        }
      }
      if ((DAT_001231c0 & 1) != 0) {
        g_log("Slirp",0x80," create new entry...");
      }
      lVar2 = local_60 + (long)*(int *)(local_60 + 0x180) * 0x18;
      *(undefined8 *)(lVar2 + 8) = local_88;
      *(undefined8 *)(lVar2 + 0x10) = local_80;
      memcpy((void *)((long)*(int *)(local_60 + 0x180) * 0x18 + local_60),local_78,6);
      *(int *)(local_60 + 0x180) = (*(int *)(local_60 + 0x180) + 1) % 0x10;
      goto LAB_001171f8;
    }
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," abort: do not register multicast or unspecified address...");
  }
LAB_001171f8:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



undefined8 FUN_0011720e(long param_1,undefined8 param_2,undefined8 param_3,undefined *param_4)

{
  char cVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  undefined8 local_88;
  undefined8 local_80;
  undefined *local_78;
  long local_70;
  int local_64;
  long local_60;
  undefined8 local_58;
  undefined8 local_50;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_60 = param_1 + 0x15cc;
  local_88 = param_2;
  local_80 = param_3;
  local_78 = param_4;
  local_70 = param_1;
  inet_ntop(10,&local_88,local_48,0x2e);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ndp_table_search...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," ip = %s",local_48);
  }
  local_58 = 0;
  local_50 = 0;
  cVar1 = FUN_00116eb4(&local_88,&local_58);
  if (cVar1 == '\x01') {
                    // WARNING: Subroutine does not return
    __assert_fail("!in6_zero(&ip_addr)",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/ndp_table.c"
                  ,0x3b,"ndp_table_search");
  }
  if ((char)local_88 == -1) {
    *local_78 = 0x33;
    local_78[1] = 0x33;
    local_78[2] = local_80._4_1_;
    local_78[3] = local_80._5_1_;
    local_78[4] = local_80._6_1_;
    local_78[5] = local_80._7_1_;
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," multicast addr = %02x:%02x:%02x:%02x:%02x:%02x",*local_78,local_78[1],
            local_78[2],local_78[3],local_78[4],local_78[5]);
    }
    uVar2 = 1;
  }
  else {
    for (local_64 = 0; local_64 < 0x10; local_64 = local_64 + 1) {
      cVar1 = FUN_00116eb4((long)local_64 * 0x18 + local_60 + 8,&local_88);
      if (cVar1 != '\0') {
        memcpy(local_78,(void *)((long)local_64 * 0x18 + local_60),6);
        if ((DAT_001231c0 & 1) != 0) {
          g_log("Slirp",0x80," found hw addr = %02x:%02x:%02x:%02x:%02x:%02x",*local_78,local_78[1],
                local_78[2],local_78[3],local_78[4],local_78[5]);
        }
        uVar2 = 1;
        goto LAB_00117549;
      }
    }
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," ip not found in table...");
    }
    uVar2 = 0;
  }
LAB_00117549:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar2;
}



undefined8 FUN_0011755f(short *param_1)

{
  undefined8 uVar1;
  
  if (*param_1 == 2) {
    uVar1 = 0x10;
  }
  else if (*param_1 == 10) {
    uVar1 = 0x1c;
  }
  else {
    uVar1 = g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.h"
                       ,0x88,"sockaddr_size",0);
  }
  return uVar1;
}



void FUN_001175b6(long param_1)

{
  *(long *)(param_1 + 0x530) = param_1 + 0x528;
  *(undefined8 *)(param_1 + 0x528) = *(undefined8 *)(param_1 + 0x530);
  *(long *)(param_1 + 0x6d0) = param_1 + 0x528;
  return;
}



void FUN_00117607(long param_1)

{
  undefined8 *puVar1;
  undefined8 local_18;
  
  local_18 = *(undefined8 **)(param_1 + 0x528);
  while (local_18 != (undefined8 *)(param_1 + 0x528)) {
    puVar1 = (undefined8 *)*local_18;
    FUN_0011787b(local_18);
    local_18 = puVar1;
  }
  return;
}



undefined8 FUN_0011765b(long param_1,long param_2,int param_3)

{
  long lVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  ssize_t sVar5;
  int *piVar6;
  char *pcVar7;
  long in_FS_OFFSET;
  sockaddr local_38;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = *(long *)(param_2 + 0x30);
  uVar2 = FUN_001081c9(2,2,1);
  *(undefined4 *)(param_1 + 0x10) = uVar2;
  if (*(int *)(param_1 + 0x10) == -1) {
    uVar4 = 0xffffffff;
  }
  else {
    iVar3 = FUN_00107a81(param_1,2);
    if (iVar3 == 0) {
      *(long *)(param_1 + 0x30) = param_2;
      *(undefined4 *)(param_1 + 0x4c) = *(undefined4 *)(lVar1 + 0x10);
      *(undefined4 *)(param_1 + 0xcc) = *(undefined4 *)(lVar1 + 0xc);
      *(undefined *)(param_1 + 0x148) = *(undefined *)(lVar1 + 1);
      *(undefined *)(param_1 + 0x14a) = 1;
      *(undefined4 *)(param_1 + 0x14c) = 4;
      *(int *)(param_1 + 0x158) = DAT_001231c8 + 240000;
      local_38.sa_family = 2;
      local_38.sa_data._2_4_ = *(undefined4 *)(param_1 + 0x4c);
      FUN_00106a33(param_1,*(long *)(param_1 + 0x28) + 0x528);
      sVar5 = sendto(*(int *)(param_1 + 0x10),(void *)(*(long *)(param_2 + 0x30) + (long)param_3),
                     (long)(*(int *)(param_2 + 0x38) - param_3),0,&local_38,0x10);
      if (sVar5 == -1) {
        if ((DAT_001231c0 & 2) != 0) {
          piVar6 = __errno_location();
          pcVar7 = strerror(*piVar6);
          piVar6 = __errno_location();
          g_log("Slirp",0x80,"icmp_input icmp sendto tx errno = %d-%s",*piVar6,pcVar7);
        }
        piVar6 = __errno_location();
        pcVar7 = strerror(*piVar6);
        FUN_00117ef4(param_2,3,0,0,pcVar7);
        FUN_0011787b(param_1);
      }
      uVar4 = 0;
    }
    else {
      close(*(int *)(param_1 + 0x10));
      *(undefined4 *)(param_1 + 0x10) = 0xffffffff;
      uVar4 = 0xffffffff;
    }
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar4;
}



void FUN_0011787b(long param_1)

{
  (**(code **)(*(long *)(*(long *)(param_1 + 0x28) + 0x1768) + 0x38))
            (*(undefined4 *)(param_1 + 0x10),*(undefined8 *)(*(long *)(param_1 + 0x28) + 6000));
  close(*(int *)(param_1 + 0x10));
  FUN_0011385c(param_1);
  return;
}



void FUN_001178d8(long param_1,int param_2)

{
  byte bVar1;
  ushort uVar2;
  long lVar3;
  byte *pbVar4;
  uint16_t uVar5;
  int iVar6;
  socklen_t __addr_len;
  long lVar7;
  int *piVar8;
  char *pcVar9;
  ssize_t sVar10;
  long in_FS_OFFSET;
  sockaddr local_a8;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  lVar3 = *(long *)(param_1 + 0x30);
  uVar2 = *(ushort *)(lVar3 + 2);
  lVar7 = *(long *)(param_1 + 0x40);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"icmp_input...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m_len = %d",*(undefined4 *)(param_1 + 0x38));
  }
  if (7 < uVar2) {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) - param_2;
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + (long)param_2;
    pbVar4 = *(byte **)(param_1 + 0x30);
    iVar6 = FUN_0010d634(param_1,uVar2);
    if (iVar6 == 0) {
      *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + param_2;
      *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) - (long)param_2;
      if ((DAT_001231c0 & 1) != 0) {
        g_log("Slirp",0x80," icmp_type = %d",*pbVar4);
      }
      bVar1 = *pbVar4;
      if (bVar1 == 0x11) {
LAB_00117eae:
        FUN_00110e00(param_1);
      }
      else {
        if ((bVar1 < 0x12) && (bVar1 < 0xe)) {
          if (10 < bVar1) goto LAB_00117eae;
          if (bVar1 < 6) {
            if (2 < bVar1) goto LAB_00117eae;
          }
          else if (bVar1 == 8) {
            *(short *)(lVar3 + 2) = *(short *)(lVar3 + 2) + (short)param_2;
            if ((*(int *)(lVar3 + 0x10) == *(int *)(lVar7 + 0x14)) ||
               (*(int *)(lVar3 + 0x10) == *(int *)(lVar7 + 0x40))) {
              FUN_001182f3(param_1);
              goto LAB_00117ed4;
            }
            if (*(int *)(lVar7 + 0x7c) == 0) {
              lVar7 = FUN_0011376d(lVar7);
              iVar6 = FUN_0011765b(lVar7,param_1,param_2);
              if (iVar6 != 0) {
                iVar6 = FUN_0010a0ab(lVar7,2);
                if (iVar6 == -1) {
                  if ((DAT_001231c0 & 2) != 0) {
                    piVar8 = __errno_location();
                    pcVar9 = strerror(*piVar8);
                    piVar8 = __errno_location();
                    g_log("Slirp",0x80,"icmp_input udp_attach errno = %d-%s",*piVar8,pcVar9);
                  }
                  FUN_0011385c(lVar7);
                  FUN_00110e00(param_1);
                }
                else {
                  *(long *)(lVar7 + 0x30) = param_1;
                  *(undefined2 *)(lVar7 + 0x48) = 2;
                  *(undefined4 *)(lVar7 + 0x4c) = *(undefined4 *)(lVar3 + 0x10);
                  uVar5 = htons(7);
                  *(uint16_t *)(lVar7 + 0x4a) = uVar5;
                  *(undefined2 *)(lVar7 + 200) = 2;
                  *(undefined4 *)(lVar7 + 0xcc) = *(undefined4 *)(lVar3 + 0xc);
                  uVar5 = htons(9);
                  *(uint16_t *)(lVar7 + 0xca) = uVar5;
                  *(undefined *)(lVar7 + 0x148) = *(undefined *)(lVar3 + 1);
                  *(undefined *)(lVar7 + 0x14a) = 1;
                  *(undefined4 *)(lVar7 + 0x14c) = 4;
                  local_a8._0_8_ = *(undefined8 *)(lVar7 + 0x48);
                  local_a8.sa_data._6_8_ = *(undefined8 *)(lVar7 + 0x50);
                  local_98 = *(undefined8 *)(lVar7 + 0x58);
                  local_90 = *(undefined8 *)(lVar7 + 0x60);
                  local_88 = *(undefined8 *)(lVar7 + 0x68);
                  local_80 = *(undefined8 *)(lVar7 + 0x70);
                  local_78 = *(undefined8 *)(lVar7 + 0x78);
                  local_70 = *(undefined8 *)(lVar7 + 0x80);
                  local_68 = *(undefined8 *)(lVar7 + 0x88);
                  local_60 = *(undefined8 *)(lVar7 + 0x90);
                  local_58 = *(undefined8 *)(lVar7 + 0x98);
                  local_50 = *(undefined8 *)(lVar7 + 0xa0);
                  local_48 = *(undefined8 *)(lVar7 + 0xa8);
                  local_40 = *(undefined8 *)(lVar7 + 0xb0);
                  local_30 = *(undefined8 *)(lVar7 + 0xc0);
                  local_38 = *(undefined8 *)(lVar7 + 0xb8);
                  iVar6 = FUN_00115f9c(lVar7,&local_a8);
                  if (iVar6 < 0) {
                    piVar8 = __errno_location();
                    pcVar9 = strerror(*piVar8);
                    FUN_00117ef4(param_1,3,0,0,pcVar9);
                    FUN_0010a15c(lVar7);
                  }
                  else {
                    __addr_len = FUN_0011755f(&local_a8);
                    sVar10 = sendto(*(int *)(lVar7 + 0x10),
                                    "This is a pseudo-PING packet used by Slirp to emulate ICMP ECHO-REQUEST packets.\n"
                                    ,0x51,0,&local_a8,__addr_len);
                    if (sVar10 == -1) {
                      if ((DAT_001231c0 & 2) != 0) {
                        piVar8 = __errno_location();
                        pcVar9 = strerror(*piVar8);
                        piVar8 = __errno_location();
                        g_log("Slirp",0x80,"icmp_input udp sendto tx errno = %d-%s",*piVar8,pcVar9);
                      }
                      piVar8 = __errno_location();
                      pcVar9 = strerror(*piVar8);
                      FUN_00117ef4(param_1,3,0,0,pcVar9);
                      FUN_0010a15c(lVar7);
                    }
                  }
                }
              }
              goto LAB_00117ed4;
            }
            goto LAB_001179d4;
          }
        }
        FUN_00110e00(param_1);
      }
      goto LAB_00117ed4;
    }
  }
LAB_001179d4:
  FUN_00110e00(param_1);
LAB_00117ed4:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00117ef4(long param_1,char param_2,char param_3,int param_4)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  uint16_t uVar4;
  undefined2 uVar5;
  uint32_t uVar6;
  int iVar7;
  char *pcVar8;
  long lVar9;
  long in_FS_OFFSET;
  uint local_78;
  undefined local_68 [32];
  undefined local_48 [24];
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"icmp_send_error...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," msrc = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," msrc_len = %d",*(undefined4 *)(param_1 + 0x38));
  }
  if (((param_2 == '\x03') || (param_2 == '\v')) && (param_1 != 0)) {
    pbVar3 = *(byte **)(param_1 + 0x30);
    if ((DAT_001231c0 & 2) != 0) {
      pcVar8 = inet_ntoa((in_addr)*(in_addr_t *)(pbVar3 + 0xc));
      FUN_0010823b(local_68,0x14,pcVar8);
      pcVar8 = inet_ntoa((in_addr)*(in_addr_t *)(pbVar3 + 0x10));
      FUN_0010823b(local_48,0x14,pcVar8);
      if ((DAT_001231c0 & 2) != 0) {
        g_log("Slirp",0x80," %.16s to %.16s",local_68,local_48);
      }
    }
    if (((*(ushort *)(pbVar3 + 6) & 0x1fff) == 0) &&
       (uVar2 = *(uint *)(pbVar3 + 0xc), uVar6 = htonl(0xfffffff), (uVar6 & uVar2) != 0)) {
      bVar1 = *pbVar3;
      local_78 = (uint)*(ushort *)(pbVar3 + 2);
      if (((pbVar3[9] != 1) ||
          ((pbVar3[(ulong)(bVar1 & 0xf) * 4] < 0x13 &&
           (*(int *)(&DAT_0011ea00 + (long)(int)(uint)pbVar3[(ulong)(bVar1 & 0xf) * 4] * 4) == 0))))
         && (lVar9 = FUN_00110cac(*(undefined8 *)(param_1 + 0x40)), lVar9 != 0)) {
        iVar7 = *(int *)(param_1 + 0x38) + 0x240;
        if (*(int *)(lVar9 + 0x24) < iVar7) {
          FUN_00111017(lVar9,iVar7);
        }
        memcpy(*(void **)(lVar9 + 0x30),*(void **)(param_1 + 0x30),(long)*(int *)(param_1 + 0x38));
        *(undefined4 *)(lVar9 + 0x38) = *(undefined4 *)(param_1 + 0x38);
        pbVar3 = *(byte **)(lVar9 + 0x30);
        *(long *)(lVar9 + 0x30) = *(long *)(lVar9 + 0x30) + 0x14;
        *(int *)(lVar9 + 0x38) = *(int *)(lVar9 + 0x38) + -0x14;
        pcVar8 = *(char **)(lVar9 + 0x30);
        if (param_4 == 0) {
          if (0x224 < local_78) {
            local_78 = 0x224;
          }
        }
        else {
          local_78 = (uint)(bVar1 & 0xf) * 4 + 8;
        }
        *(uint *)(lVar9 + 0x38) = local_78 + 8;
        *pcVar8 = param_2;
        pcVar8[1] = param_3;
        pcVar8[4] = '\0';
        pcVar8[5] = '\0';
        pcVar8[6] = '\0';
        pcVar8[7] = '\0';
        memcpy(pcVar8 + 8,*(void **)(param_1 + 0x30),(ulong)local_78);
        uVar4 = htons(*(uint16_t *)(pcVar8 + 10));
        *(uint16_t *)(pcVar8 + 10) = uVar4;
        uVar4 = htons(*(uint16_t *)(pcVar8 + 0xc));
        *(uint16_t *)(pcVar8 + 0xc) = uVar4;
        uVar4 = htons(*(uint16_t *)(pcVar8 + 0xe));
        *(uint16_t *)(pcVar8 + 0xe) = uVar4;
        pcVar8[2] = '\0';
        pcVar8[3] = '\0';
        uVar5 = FUN_0010d634(lVar9,*(undefined4 *)(lVar9 + 0x38));
        *(undefined2 *)(pcVar8 + 2) = uVar5;
        *(long *)(lVar9 + 0x30) = *(long *)(lVar9 + 0x30) + -0x14;
        *(int *)(lVar9 + 0x38) = *(int *)(lVar9 + 0x38) + 0x14;
        *pbVar3 = *pbVar3 & 0xf0 | 5;
        *(short *)(pbVar3 + 2) = (short)*(undefined4 *)(lVar9 + 0x38);
        pbVar3[1] = pbVar3[1] & 0x1e | 0xc0;
        pbVar3[8] = 0xff;
        pbVar3[9] = 1;
        *(undefined4 *)(pbVar3 + 0x10) = *(undefined4 *)(pbVar3 + 0xc);
        *(undefined4 *)(pbVar3 + 0xc) = *(undefined4 *)(*(long *)(lVar9 + 0x40) + 0x14);
        FUN_001196c1(0,lVar9);
      }
    }
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_001182f3(long param_1)

{
  undefined4 uVar1;
  byte *pbVar2;
  undefined *puVar3;
  uint uVar4;
  undefined2 uVar5;
  int iVar6;
  int iVar7;
  
  pbVar2 = *(byte **)(param_1 + 0x30);
  uVar4 = (uint)(*pbVar2 & 0xf);
  iVar6 = uVar4 * 4;
  iVar7 = iVar6 + -0x14;
  *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + (long)iVar6;
  *(uint *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + uVar4 * -4;
  puVar3 = *(undefined **)(param_1 + 0x30);
  *puVar3 = 0;
  *(undefined2 *)(puVar3 + 2) = 0;
  uVar5 = FUN_0010d634(param_1,(uint)*(ushort *)(pbVar2 + 2) + uVar4 * -4);
  *(undefined2 *)(puVar3 + 2) = uVar5;
  *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) - (long)iVar6;
  *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + iVar6;
  if (0 < iVar7) {
    memmove(pbVar2 + 0x14,pbVar2 + iVar6,(ulong)(*(int *)(param_1 + 0x38) + uVar4 * -4));
    *pbVar2 = *pbVar2 & 0xf0 | (byte)(iVar6 - iVar7 >> 2) & 0xf;
    *(short *)(pbVar2 + 2) = *(short *)(pbVar2 + 2) - (short)iVar7;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) - iVar7;
  }
  pbVar2[8] = 0xff;
  uVar1 = *(undefined4 *)(pbVar2 + 0x10);
  *(undefined4 *)(pbVar2 + 0x10) = *(undefined4 *)(pbVar2 + 0xc);
  *(undefined4 *)(pbVar2 + 0xc) = uVar1;
  FUN_001196c1(0,param_1);
  return;
}



void FUN_0011844e(long param_1)

{
  undefined2 uVar1;
  long lVar2;
  void *__buf;
  uint uVar3;
  int iVar4;
  ssize_t sVar5;
  int *piVar6;
  char *pcVar7;
  size_t __n;
  
  lVar2 = *(long *)(param_1 + 0x30);
  uVar3 = (uint)(**(byte **)(lVar2 + 0x30) & 0xf);
  iVar4 = uVar3 * 4;
  *(long *)(lVar2 + 0x30) = *(long *)(lVar2 + 0x30) + (long)iVar4;
  *(uint *)(lVar2 + 0x38) = *(int *)(lVar2 + 0x38) + uVar3 * -4;
  __buf = *(void **)(lVar2 + 0x30);
  uVar1 = *(undefined2 *)((long)__buf + 4);
  if ((*(uint *)(lVar2 + 0x20) & 1) == 0) {
    __n = (lVar2 + 0x60 + (long)*(int *)(lVar2 + 0x24)) - *(long *)(lVar2 + 0x30);
  }
  else {
    __n = (*(long *)(lVar2 + 0x58) + (long)*(int *)(lVar2 + 0x24)) - *(long *)(lVar2 + 0x30);
  }
  sVar5 = recv(*(int *)(param_1 + 0x10),__buf,__n,0);
  *(undefined2 *)((long)__buf + 4) = uVar1;
  *(long *)(lVar2 + 0x30) = *(long *)(lVar2 + 0x30) - (long)iVar4;
  *(int *)(lVar2 + 0x38) = *(int *)(lVar2 + 0x38) + iVar4;
  if (((int)sVar5 == -1) || ((int)sVar5 == 0)) {
    piVar6 = __errno_location();
    iVar4 = *piVar6;
    if ((DAT_001231c0 & 2) != 0) {
      piVar6 = __errno_location();
      pcVar7 = strerror(*piVar6);
      piVar6 = __errno_location();
      g_log("Slirp",0x80," udp icmp rx errno = %d-%s",*piVar6,pcVar7);
    }
    piVar6 = __errno_location();
    pcVar7 = strerror(*piVar6);
    FUN_00117ef4(*(undefined8 *)(param_1 + 0x30),3,iVar4 != 0x65,0,pcVar7);
  }
  else {
    FUN_001182f3(*(undefined8 *)(param_1 + 0x30));
    *(undefined8 *)(param_1 + 0x30) = 0;
  }
  FUN_0011787b(param_1);
  return;
}



undefined2 * FUN_00118650(long param_1,int *param_2,void *param_3)

{
  int iVar1;
  uint32_t uVar2;
  long lVar3;
  undefined2 *puVar4;
  uint32_t local_24;
  
  local_24 = 0;
  while( true ) {
    if (0xf < (int)local_24) {
      return (undefined2 *)0x0;
    }
    lVar3 = param_1 + ((long)(int)local_24 + 0x22) * 8;
    if ((*(short *)(lVar3 + 10) == 0) ||
       (iVar1 = memcmp(param_3,(void *)(lVar3 + 0xc),6), iVar1 == 0)) break;
    local_24 = local_24 + 1;
  }
  puVar4 = (undefined2 *)(param_1 + ((long)(int)local_24 + 0x22) * 8 + 10);
  *puVar4 = 1;
  iVar1 = *(int *)(param_1 + 0x3c);
  uVar2 = htonl(local_24);
  *param_2 = iVar1 + uVar2;
  return puVar4;
}



short * FUN_00118722(long param_1,uint32_t *param_2,void *param_3)

{
  uint32_t uVar1;
  uint32_t uVar2;
  int iVar3;
  short *psVar4;
  
  uVar1 = ntohl(*param_2);
  uVar2 = ntohl(*(uint32_t *)(param_1 + 0x3c));
  if ((uVar1 < uVar2) || (uVar2 + 0x10 <= uVar1)) {
LAB_001187cc:
    psVar4 = (short *)0x0;
  }
  else {
    param_1 = param_1 + ((ulong)(uVar1 - uVar2) + 0x22) * 8;
    psVar4 = (short *)(param_1 + 10);
    if (*psVar4 != 0) {
      iVar3 = memcmp(param_3,(void *)(param_1 + 0xc),6);
      if (iVar3 != 0) goto LAB_001187cc;
    }
    *psVar4 = 1;
  }
  return psVar4;
}



undefined2 * FUN_001187d3(long param_1,int *param_2,void *param_3)

{
  int iVar1;
  uint32_t uVar2;
  undefined2 *puVar3;
  uint32_t local_24;
  
  local_24 = 0;
  while( true ) {
    if (0xf < (int)local_24) {
      return (undefined2 *)0x0;
    }
    iVar1 = memcmp(param_3,(void *)(param_1 + ((long)(int)local_24 + 0x22) * 8 + 0xc),6);
    if (iVar1 == 0) break;
    local_24 = local_24 + 1;
  }
  puVar3 = (undefined2 *)(param_1 + ((long)(int)local_24 + 0x22) * 8 + 10);
  *puVar3 = 1;
  iVar1 = *(int *)(param_1 + 0x3c);
  uVar2 = htonl(local_24);
  *param_2 = iVar1 + uVar2;
  return puVar3;
}



void FUN_0011888d(long param_1,uint *param_2,uint32_t *param_3)

{
  uint32_t *puVar1;
  byte bVar2;
  uint32_t uVar3;
  int iVar4;
  uint uVar5;
  uint32_t uVar6;
  byte *pbVar7;
  byte *local_28;
  
  *param_2 = 0;
  uVar3 = htonl(0);
  *param_3 = uVar3;
  pbVar7 = (byte *)(param_1 + 0x240);
  iVar4 = memcmp((void *)(param_1 + 0x108),&DAT_0011eb80,4);
  if (iVar4 == 0) {
    local_28 = (byte *)(param_1 + 0x10c);
    while (local_28 < pbVar7) {
      bVar2 = *local_28;
      if (bVar2 == 0) {
        local_28 = local_28 + 1;
      }
      else {
        if ((bVar2 == 0xff) || (pbVar7 <= local_28 + 1)) break;
        puVar1 = (uint32_t *)(local_28 + 2);
        uVar5 = (uint)local_28[1];
        if (pbVar7 < (byte *)((long)puVar1 + (long)(int)uVar5)) break;
        if ((DAT_001231c0 & 1) != 0) {
          g_log("Slirp",0x80,"dhcp: tag=%d len=%d\n...",bVar2,uVar5);
        }
        if (bVar2 == 0x32) {
          if (3 < uVar5) {
            *param_3 = *puVar1;
          }
        }
        else if ((bVar2 == 0x35) && (uVar5 != 0)) {
          *param_2 = (uint)*(byte *)puVar1;
        }
        local_28 = (byte *)((long)puVar1 + (long)(int)uVar5);
      }
    }
    if (((*param_2 == 3) && (uVar3 = *param_3, uVar6 = htonl(0), uVar3 == uVar6)) &&
       (*(int *)(param_1 + 0x28) != 0)) {
      *param_3 = *(uint32_t *)(param_1 + 0x28);
    }
  }
  return;
}



void FUN_00118a47(long param_1,long param_2)

{
  undefined *puVar1;
  uint32_t *puVar2;
  uint32_t uVar3;
  uint32_t uVar4;
  char *pcVar5;
  size_t sVar6;
  long in_FS_OFFSET;
  uint32_t local_7c;
  int local_78;
  uint32_t local_74;
  long local_70;
  uint32_t *local_68;
  long local_60;
  void *local_58;
  uint32_t *local_50;
  undefined local_48 [2];
  uint16_t local_46;
  undefined4 local_44;
  undefined local_38 [2];
  uint16_t local_36;
  uint32_t local_34 [3];
  undefined4 local_26;
  undefined2 local_22;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_70 = 0;
  FUN_0011888d(param_2,&local_78,&local_7c);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"bootp packet op=%d msgtype=%d...",*(undefined *)(param_2 + 0x1c),local_78);
  }
  uVar4 = local_7c;
  uVar3 = htonl(0);
  if (uVar4 == uVar3) {
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80,&DAT_0011ebdc);
    }
  }
  else if ((DAT_001231c0 & 1) != 0) {
    uVar4 = ntohl(local_7c);
    g_log("Slirp",0x80," req_addr=%08x\n...",uVar4);
  }
  if (local_78 == 0) {
    local_78 = 3;
  }
  if ((local_78 != 1) && (local_78 != 3)) goto LAB_001193fe;
  local_26 = *(undefined4 *)(param_2 + 0x38);
  local_22 = *(undefined2 *)(param_2 + 0x3c);
  local_60 = FUN_00110cac(param_1);
  if (local_60 == 0) goto LAB_001193fe;
  *(long *)(local_60 + 0x30) = *(long *)(local_60 + 0x30) + 0x10;
  local_58 = *(void **)(local_60 + 0x30);
  *(long *)(local_60 + 0x30) = *(long *)(local_60 + 0x30) + 0x1c;
  memset(local_58,0,0x240);
  uVar4 = local_7c;
  if (local_78 == 1) {
    uVar3 = htonl(0);
    if ((uVar4 != uVar3) && (local_70 = FUN_00118722(param_1,&local_7c,&local_26), local_70 != 0)) {
      local_34[0] = local_7c;
    }
    if (local_70 == 0) {
LAB_00118c3e:
      local_70 = FUN_00118650(param_1,local_34,&local_26);
      if (local_70 == 0) {
        if ((DAT_001231c0 & 1) != 0) {
          g_log("Slirp",0x80,"no address left\n...");
        }
        goto LAB_001193fe;
      }
    }
    *(undefined4 *)(local_70 + 2) = local_26;
    *(undefined2 *)(local_70 + 6) = local_22;
  }
  else {
    uVar3 = htonl(0);
    if (uVar4 == uVar3) {
      local_70 = FUN_001187d3(param_1,local_34,param_2 + 0x38);
      if (local_70 == 0) goto LAB_00118c3e;
    }
    else {
      local_70 = FUN_00118722(param_1,&local_7c,&local_26);
      if (local_70 == 0) {
        local_34[0] = 0xffffffff;
      }
      else {
        local_34[0] = local_7c;
        *(undefined4 *)(local_70 + 2) = local_26;
        *(undefined2 *)(local_70 + 6) = local_22;
      }
    }
  }
  FUN_00107c71(param_1,local_34[0],&local_26);
  local_44 = *(undefined4 *)(param_1 + 0x14);
  local_46 = htons(0x43);
  local_36 = htons(0x44);
  *(undefined *)((long)local_58 + 0x1c) = 2;
  *(undefined4 *)((long)local_58 + 0x20) = *(undefined4 *)(param_2 + 0x20);
  *(undefined *)((long)local_58 + 0x1d) = 1;
  *(undefined *)((long)local_58 + 0x1e) = 6;
  memcpy((void *)((long)local_58 + 0x38),(void *)(param_2 + 0x38),6);
  *(uint32_t *)((long)local_58 + 0x2c) = local_34[0];
  *(undefined4 *)((long)local_58 + 0x30) = local_44;
  local_50 = (uint32_t *)((long)local_58 + 0x240);
  *(undefined4 *)((long)local_58 + 0x108) = 0x63538263;
  local_68 = (uint32_t *)((long)local_58 + 0x10c);
  if (local_70 == 0) {
    if ((DAT_001231c0 & 1) != 0) {
      uVar4 = ntohl(local_7c);
      g_log("Slirp",0x80,"nak\'ed addr=%08x\n...",uVar4);
    }
    *(undefined *)local_68 = 0x35;
    *(undefined *)((long)local_68 + 1) = 1;
    *(undefined *)((long)local_68 + 2) = 6;
    puVar1 = (undefined *)((long)local_68 + 4);
    *(undefined *)((long)local_68 + 3) = 0x38;
    local_68 = (uint32_t *)((long)local_68 + 5);
    *puVar1 = 0x1f;
    memcpy(local_68,"requested address not available",0x1f);
    local_68 = (uint32_t *)((long)local_68 + 0x1f);
  }
  else {
    if ((DAT_001231c0 & 1) != 0) {
      uVar4 = ntohl(local_34[0]);
      if (local_78 == 1) {
        pcVar5 = "offered";
      }
      else {
        pcVar5 = "ack\'ed";
      }
      g_log("Slirp",0x80,"%s addr=%08x\n...",pcVar5,uVar4);
    }
    if (local_78 == 1) {
      *(undefined *)local_68 = 0x35;
      *(undefined *)((long)local_68 + 1) = 1;
      *(undefined *)((long)local_68 + 2) = 2;
    }
    else {
      *(undefined *)local_68 = 0x35;
      *(undefined *)((long)local_68 + 1) = 1;
      *(undefined *)((long)local_68 + 2) = 5;
    }
    local_68 = (uint32_t *)((long)local_68 + 3);
    if (*(long *)(param_1 + 0x1a0) != 0) {
      sVar6 = strlen(*(char **)(param_1 + 0x1a0));
      if (0x7f < sVar6) {
        g_assertion_message_expr
                  ("Slirp",
                   "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/bootp.c"
                   ,0x102,"bootp_reply","strlen(slirp->bootp_filename) < sizeof(rbp->bp_file)");
      }
      strcpy((char *)((long)local_58 + 0x88),*(char **)(param_1 + 0x1a0));
    }
    *(undefined *)local_68 = 0x36;
    *(undefined *)((long)local_68 + 1) = 4;
    *(undefined4 *)((long)local_68 + 2) = local_44;
    *(undefined *)((long)local_68 + 6) = 1;
    *(undefined *)((long)local_68 + 7) = 4;
    *(undefined4 *)((long)local_68 + 8) = *(undefined4 *)(param_1 + 0x10);
    puVar2 = (uint32_t *)((long)local_68 + 0xc);
    if (*(int *)(param_1 + 0x7c) == 0) {
      *(undefined *)((long)local_68 + 0xc) = 3;
      *(undefined *)((long)local_68 + 0xd) = 4;
      *(undefined4 *)((long)local_68 + 0xe) = local_44;
      *(undefined *)((long)local_68 + 0x12) = 6;
      *(undefined *)((long)local_68 + 0x13) = 4;
      *(undefined4 *)((long)local_68 + 0x14) = *(undefined4 *)(param_1 + 0x40);
      puVar2 = (uint32_t *)((long)local_68 + 0x18);
    }
    local_68 = puVar2;
    puVar1 = (undefined *)((long)local_68 + 1);
    *(undefined *)local_68 = 0x33;
    local_68 = (uint32_t *)((long)local_68 + 2);
    *puVar1 = 4;
    local_74 = htonl(0x15180);
    *local_68 = local_74;
    local_68 = local_68 + 1;
    if (*(char *)(param_1 + 0x58) != '\0') {
      sVar6 = strlen((char *)(param_1 + 0x58));
      local_74 = (uint32_t)sVar6;
      if ((uint32_t *)((long)local_68 + (long)(int)local_74 + 2) < local_50) {
        puVar1 = (undefined *)((long)local_68 + 1);
        *(undefined *)local_68 = 0xc;
        local_68 = (uint32_t *)((long)local_68 + 2);
        *puVar1 = (char)sVar6;
        memcpy(local_68,(void *)(param_1 + 0x58),(long)(int)local_74);
        local_68 = (uint32_t *)((long)local_68 + (long)(int)local_74);
      }
      else {
        g_log("Slirp",0x10,"DHCP packet size exceeded, omitting host name option.");
      }
    }
    if (*(long *)(param_1 + 0x1b8) != 0) {
      sVar6 = strlen(*(char **)(param_1 + 0x1b8));
      local_74 = (uint32_t)sVar6;
      if ((uint32_t *)((long)local_68 + (long)(int)local_74 + 2) < local_50) {
        puVar1 = (undefined *)((long)local_68 + 1);
        *(undefined *)local_68 = 0xf;
        local_68 = (uint32_t *)((long)local_68 + 2);
        *puVar1 = (char)sVar6;
        memcpy(local_68,*(void **)(param_1 + 0x1b8),(long)(int)local_74);
        local_68 = (uint32_t *)((long)local_68 + (long)(int)local_74);
      }
      else {
        g_log("Slirp",0x10,"DHCP packet size exceeded, omitting domain name option.");
      }
    }
    if (*(long *)(param_1 + 0x1400) != 0) {
      sVar6 = strlen(*(char **)(param_1 + 0x1400));
      local_74 = (uint32_t)sVar6;
      if ((uint32_t *)((long)local_68 + (long)(int)local_74 + 2) < local_50) {
        puVar1 = (undefined *)((long)local_68 + 1);
        *(undefined *)local_68 = 0x42;
        local_68 = (uint32_t *)((long)local_68 + 2);
        *puVar1 = (char)sVar6;
        memcpy(local_68,*(void **)(param_1 + 0x1400),(long)(int)local_74);
        local_68 = (uint32_t *)((long)local_68 + (long)(int)local_74);
      }
      else {
        g_log("Slirp",0x10,"DHCP packet size exceeded, omitting tftp-server-name option.");
      }
    }
    if (*(long *)(param_1 + 0x1b0) != 0) {
      local_74 = (uint32_t)*(undefined8 *)(param_1 + 0x1a8);
      if ((uint32_t *)((long)local_68 + (long)(int)local_74) < local_50) {
        memcpy(local_68,*(void **)(param_1 + 0x1b0),(long)(int)local_74);
        local_68 = (uint32_t *)((long)local_68 + (long)(int)local_74);
      }
      else {
        g_log("Slirp",0x10,"DHCP packet size exceeded, omitting domain-search option.");
      }
    }
  }
  if (local_50 <= local_68) {
                    // WARNING: Subroutine does not return
    __assert_fail("q < end",
                  "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/bootp.c"
                  ,0x161,"bootp_reply");
  }
  *(undefined *)local_68 = 0xff;
  local_34[0] = 0xffffffff;
  *(undefined4 *)(local_60 + 0x38) = 0x224;
  FUN_00109e86(0,local_60,local_48,local_38,0x10);
LAB_001193fe:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0011941c(long param_1)

{
  if (*(char *)(*(long *)(param_1 + 0x30) + 0x1c) == '\x01') {
    FUN_00118a47(*(undefined8 *)(param_1 + 0x40),*(long *)(param_1 + 0x30));
  }
  return;
}



void FUN_0011945e(undefined8 param_1)

{
  FUN_001116e0(param_1);
  return;
}



void FUN_0011947d(undefined8 param_1)

{
  FUN_001117e3(param_1);
  return;
}



void FUN_0011949c(long param_1)

{
  byte bVar1;
  int iVar2;
  long lVar3;
  byte *pbVar4;
  uint16_t uVar5;
  
  lVar3 = *(long *)(param_1 + 0x40);
  if (*(char *)(lVar3 + 10) == '\x01') {
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80,"ip6_input...");
    }
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," m = %p",param_1);
    }
    if ((DAT_001231c0 & 1) != 0) {
      g_log("Slirp",0x80," m_len = %d",*(undefined4 *)(param_1 + 0x38));
    }
    if ((0x27 < *(uint *)(param_1 + 0x38)) &&
       (pbVar4 = *(byte **)(param_1 + 0x30), (*pbVar4 & 0xf0) == 0x60)) {
      uVar5 = ntohs(*(uint16_t *)(pbVar4 + 4));
      if ((ulong)(long)*(int *)(lVar3 + 0x88) < (ulong)uVar5 + 0x28) {
        FUN_00111956(param_1,2,0);
      }
      else {
        iVar2 = *(int *)(param_1 + 0x38);
        uVar5 = ntohs(*(uint16_t *)(pbVar4 + 4));
        if ((ulong)uVar5 + 0x28 <= (ulong)(long)iVar2) {
          if (pbVar4[7] != 0) {
            bVar1 = pbVar4[6];
            if (bVar1 == 0x3a) {
              FUN_00112b19(param_1);
              return;
            }
            if (bVar1 < 0x3b) {
              if (bVar1 == 6) {
                uVar5 = ntohs(*(uint16_t *)(pbVar4 + 4));
                *(uint16_t *)(pbVar4 + 4) = uVar5;
                FUN_0010a803(param_1,0x28,0,10);
                return;
              }
              if (bVar1 == 0x11) {
                FUN_0011adcb(param_1);
                return;
              }
            }
            FUN_00110e00(param_1);
            return;
          }
          FUN_00111956(param_1,3,0);
        }
      }
    }
  }
  FUN_00110e00(param_1);
  return;
}



int FUN_001196c1(undefined8 param_1,long param_2)

{
  long lVar1;
  byte *pbVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  uint16_t uVar5;
  undefined2 uVar6;
  uint uVar7;
  int iVar8;
  long lVar9;
  long local_70;
  uint local_4c;
  int local_48;
  int local_44;
  long *local_38;
  
  lVar1 = *(long *)(param_2 + 0x40);
  local_44 = 0;
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"ip_output...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m0 = %p",param_2);
  }
  pbVar2 = *(byte **)(param_2 + 0x30);
  *pbVar2 = *pbVar2 & 0xf | 0x40;
  *(ushort *)(pbVar2 + 6) = *(ushort *)(pbVar2 + 6) & 0x4000;
  uVar5 = *(uint16_t *)(lVar1 + 0x118);
  *(uint16_t *)(lVar1 + 0x118) = uVar5 + 1;
  uVar5 = htons(uVar5);
  *(uint16_t *)(pbVar2 + 4) = uVar5;
  *pbVar2 = *pbVar2 & 0xf0 | 5;
  if (*(int *)(lVar1 + 0x88) < (int)(uint)*(ushort *)(pbVar2 + 2)) {
    if (((*(ushort *)(pbVar2 + 6) & 0x4000) == 0) &&
       (uVar7 = *(int *)(lVar1 + 0x88) - 0x14U & 0xfffffff8, 7 < (int)uVar7)) {
      local_38 = (long *)(param_2 + 0x10);
      local_4c = uVar7;
      for (local_48 = uVar7 + 0x14; local_48 < (int)(uint)*(ushort *)(pbVar2 + 2);
          local_48 = local_48 + local_4c) {
        lVar9 = FUN_00110cac(lVar1);
        if (lVar9 == 0) {
          local_44 = -1;
          local_70 = param_2;
          goto LAB_00119ab5;
        }
        *(long *)(lVar9 + 0x30) = *(long *)(lVar9 + 0x30) + 0x10;
        puVar3 = *(undefined8 **)(lVar9 + 0x30);
        uVar4 = *(undefined8 *)(pbVar2 + 8);
        *puVar3 = *(undefined8 *)pbVar2;
        puVar3[1] = uVar4;
        *(undefined4 *)(puVar3 + 2) = *(undefined4 *)(pbVar2 + 0x10);
        *(undefined4 *)(lVar9 + 0x38) = 0x14;
        *(ushort *)((long)puVar3 + 6) =
             (*(ushort *)(pbVar2 + 6) & 0xdfff) + (short)(local_48 + -0x14 >> 3);
        if ((*(ushort *)(pbVar2 + 6) & 0x2000) != 0) {
          *(ushort *)((long)puVar3 + 6) = *(ushort *)((long)puVar3 + 6) | 0x2000;
        }
        if ((int)(local_48 + local_4c) < (int)(uint)*(ushort *)(pbVar2 + 2)) {
          *(ushort *)((long)puVar3 + 6) = *(ushort *)((long)puVar3 + 6) | 0x2000;
        }
        else {
          local_4c = (uint)*(ushort *)(pbVar2 + 2) - local_48;
        }
        uVar5 = htons((short)local_4c + 0x14);
        *(uint16_t *)((long)puVar3 + 2) = uVar5;
        iVar8 = FUN_001111d7(lVar9,param_2,local_48,local_4c);
        if (iVar8 < 0) {
          local_44 = -1;
          local_70 = param_2;
          goto LAB_00119ab5;
        }
        uVar5 = htons(*(uint16_t *)((long)puVar3 + 6));
        *(uint16_t *)((long)puVar3 + 6) = uVar5;
        *(undefined2 *)((long)puVar3 + 10) = 0;
        uVar6 = FUN_0010d634(lVar9,0x14);
        *(undefined2 *)((long)puVar3 + 10) = uVar6;
        *local_38 = lVar9;
        local_38 = (long *)(lVar9 + 0x10);
      }
      FUN_00111173(param_2,(uVar7 + 0x14) - (uint)*(ushort *)(pbVar2 + 2));
      uVar5 = htons((uint16_t)*(undefined4 *)(param_2 + 0x38));
      *(uint16_t *)(pbVar2 + 2) = uVar5;
      uVar5 = htons(*(ushort *)(pbVar2 + 6) | 0x2000);
      *(uint16_t *)(pbVar2 + 6) = uVar5;
      pbVar2[10] = 0;
      pbVar2[0xb] = 0;
      uVar6 = FUN_0010d634(param_2,0x14);
      *(undefined2 *)(pbVar2 + 10) = uVar6;
      local_70 = param_2;
LAB_00119ab5:
      while (local_70 != 0) {
        lVar1 = *(long *)(local_70 + 0x10);
        *(undefined8 *)(local_70 + 0x10) = 0;
        if (local_44 == 0) {
          FUN_0010d15e(param_1);
          local_70 = lVar1;
        }
        else {
          FUN_00110e00(local_70);
          local_70 = lVar1;
        }
      }
    }
    else {
      local_44 = -1;
      FUN_00110e00(param_2);
    }
  }
  else {
    uVar5 = htons(*(uint16_t *)(pbVar2 + 2));
    *(uint16_t *)(pbVar2 + 2) = uVar5;
    uVar5 = htons(*(uint16_t *)(pbVar2 + 6));
    *(uint16_t *)(pbVar2 + 6) = uVar5;
    pbVar2[10] = 0;
    pbVar2[0xb] = 0;
    uVar6 = FUN_0010d634(param_2,0x14);
    *(undefined2 *)(pbVar2 + 10) = uVar6;
    FUN_0010d15e(param_1,param_2);
  }
  return local_44;
}



undefined8 FUN_00119adb(void *param_1,void *param_2)

{
  int iVar1;
  undefined4 extraout_var;
  
  iVar1 = memcmp(param_1,param_2,0x10);
  return CONCAT71((int7)(CONCAT44(extraout_var,iVar1) >> 8),iVar1 == 0);
}



undefined8 FUN_00119b0a(short *param_1,short *param_2)

{
  char cVar1;
  undefined8 uVar2;
  
  if (*param_1 == *param_2) {
    if (*param_1 == 2) {
      if ((*(int *)(param_1 + 2) == *(int *)(param_2 + 2)) && (param_1[1] == param_2[1])) {
        uVar2 = 1;
      }
      else {
        uVar2 = 0;
      }
    }
    else if (*param_1 == 10) {
      cVar1 = FUN_00119adb(param_1 + 4,param_2 + 4);
      if ((cVar1 == '\0') || (param_1[1] != param_2[1])) {
        uVar2 = 0;
      }
      else {
        uVar2 = 1;
      }
    }
    else {
      uVar2 = g_assertion_message_expr
                        ("Slirp",
                         "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.h"
                         ,0x7a,"sockaddr_equal",0);
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



undefined8 FUN_00119c0e(short *param_1)

{
  undefined8 uVar1;
  
  if (*param_1 == 2) {
    uVar1 = 0x10;
  }
  else if (*param_1 == 10) {
    uVar1 = 0x1c;
  }
  else {
    uVar1 = g_assertion_message_expr
                      ("Slirp",
                       "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/socket.h"
                       ,0x88,"sockaddr_size",0);
  }
  return uVar1;
}



bool FUN_00119c65(long *param_1)

{
  return *param_1 != 0;
}



void FUN_00119c7f(long param_1)

{
  *(undefined4 *)(param_1 + 0xa0) = DAT_001231c8;
  return;
}



void FUN_00119c9c(undefined8 *param_1)

{
  if (-1 < *(int *)(param_1 + 2)) {
    close(*(int *)(param_1 + 2));
    *(undefined4 *)(param_1 + 2) = 0xffffffff;
  }
  g_free(param_1[1]);
  *param_1 = 0;
  return;
}



int FUN_00119cee(long param_1,void *param_2,undefined2 *param_3)

{
  int iVar1;
  uint uVar2;
  long *__s;
  int local_14;
  
  local_14 = 0;
  while( true ) {
    if (0x13 < local_14) {
      return -1;
    }
    __s = (long *)(param_1 + (long)local_14 * 0xa8 + 0x6e0);
    iVar1 = FUN_00119c65(__s);
    if (iVar1 == 0) break;
    if (5000 < DAT_001231c8 - *(int *)(__s + 0x14)) {
      FUN_00119c9c(__s);
      break;
    }
    local_14 = local_14 + 1;
  }
  memset(__s,0,0xa8);
  uVar2 = FUN_00119c0e(param_2);
  memcpy(__s + 3,param_2,(ulong)uVar2);
  *(undefined4 *)(__s + 2) = 0xffffffff;
  *(undefined2 *)((long)__s + 0x14) = 0x200;
  *(undefined2 *)(__s + 0x13) = *param_3;
  *__s = param_1;
  FUN_00119c7f(__s);
  return local_14;
}



int FUN_00119e05(long param_1,undefined8 param_2,short *param_3)

{
  int iVar1;
  long lVar2;
  int local_14;
  
  local_14 = 0;
  while( true ) {
    if (0x13 < local_14) {
      return -1;
    }
    lVar2 = param_1 + (long)local_14 * 0xa8 + 0x6e0;
    iVar1 = FUN_00119c65(lVar2);
    if (((iVar1 != 0) && (iVar1 = FUN_00119b0a(lVar2 + 0x18,param_2), iVar1 != 0)) &&
       (*(short *)(lVar2 + 0x98) == *param_3)) break;
    local_14 = local_14 + 1;
  }
  return local_14;
}



undefined4 FUN_00119eab(long param_1,int param_2,void *param_3,int param_4)

{
  int iVar1;
  __off_t _Var2;
  ssize_t sVar3;
  undefined4 local_c;
  
  local_c = 0;
  if (*(int *)(param_1 + 0x10) < 0) {
    iVar1 = open(*(char **)(param_1 + 8),0);
    *(int *)(param_1 + 0x10) = iVar1;
  }
  if (*(int *)(param_1 + 0x10) < 0) {
    local_c = 0xffffffff;
  }
  else if (param_4 != 0) {
    _Var2 = lseek(*(int *)(param_1 + 0x10),(ulong)((uint)*(ushort *)(param_1 + 0x14) * param_2),0);
    if (_Var2 == -1) {
      local_c = 0xffffffff;
    }
    else {
      sVar3 = read(*(int *)(param_1 + 0x10),param_3,(long)param_4);
      local_c = (undefined4)sVar3;
    }
  }
  return local_c;
}



undefined8 FUN_00119f67(long param_1,long param_2)

{
  undefined8 uVar1;
  
  memset(*(void **)(param_2 + 0x30),0,(long)*(int *)(param_2 + 0x24));
  *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + 0x10;
  if (*(short *)(param_1 + 0x18) == 10) {
    *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + 0x28;
  }
  else {
    *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + 0x14;
  }
  uVar1 = *(undefined8 *)(param_2 + 0x30);
  *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + 8;
  return uVar1;
}



void FUN_0011a00c(long *param_1,undefined8 param_2,long param_3)

{
  long in_FS_OFFSET;
  undefined local_58 [2];
  undefined2 local_56;
  undefined4 local_54;
  undefined8 local_50;
  undefined8 local_48;
  undefined local_38 [2];
  undefined2 local_36;
  undefined4 local_34;
  long local_30;
  long local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (*(short *)(param_1 + 3) == 10) {
    local_48 = *(undefined8 *)(*param_1 + 0x34);
    local_50 = *(undefined8 *)(*param_1 + 0x2c);
    local_56 = *(undefined2 *)(param_3 + 2);
    local_28 = param_1[5];
    local_30 = param_1[4];
    local_36 = *(undefined2 *)(param_1 + 0x13);
    FUN_0011b588(0,param_2,local_58,local_38);
  }
  else {
    local_54 = *(undefined4 *)(*param_1 + 0x14);
    local_56 = *(undefined2 *)(param_3 + 2);
    local_34 = *(undefined4 *)((long)param_1 + 0x1c);
    local_36 = *(undefined2 *)(param_1 + 0x13);
    FUN_00109e86(0,param_2,local_58,local_38,0x10);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



undefined8
FUN_0011a112(undefined8 *param_1,long param_2,long param_3,int param_4,undefined8 param_5)

{
  uint16_t uVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  long lVar5;
  int local_20;
  int local_1c;
  
  local_1c = 0;
  lVar3 = FUN_00110cac(*param_1);
  if (lVar3 == 0) {
    uVar4 = 0xffffffff;
  }
  else {
    lVar5 = FUN_00119f67(param_1,lVar3);
    uVar1 = htons(6);
    *(uint16_t *)(lVar5 + 8) = uVar1;
    for (local_20 = 0; local_20 < param_4; local_20 = local_20 + 1) {
      iVar2 = FUN_00108442(lVar5 + 10 + (long)local_1c,0x596 - (long)local_1c,&DAT_0011eeda,
                           *(undefined8 *)(param_2 + (long)local_20 * 8));
      local_1c = local_1c + iVar2;
      iVar2 = FUN_00108442(lVar5 + 10 + (long)local_1c,0x596 - (long)local_1c,&DAT_0011eedd,
                           *(undefined4 *)(param_3 + (long)local_20 * 4));
      local_1c = local_1c + iVar2;
    }
    *(int *)(lVar3 + 0x38) = local_1c + 2;
    FUN_0011a00c(param_1,lVar3,param_5);
    uVar4 = 0;
  }
  return uVar4;
}



void FUN_0011a26e(undefined8 *param_1,uint16_t param_2,char *param_3,undefined8 param_4)

{
  uint16_t uVar1;
  long lVar2;
  long lVar3;
  size_t sVar4;
  
  if ((DAT_001231c0 & 8) != 0) {
    g_log("Slirp",0x80,"tftp error msg: %s",param_3);
  }
  lVar2 = FUN_00110cac(*param_1);
  if (lVar2 != 0) {
    lVar3 = FUN_00119f67(param_1,lVar2);
    uVar1 = htons(5);
    *(uint16_t *)(lVar3 + 8) = uVar1;
    uVar1 = htons(param_2);
    *(uint16_t *)(lVar3 + 10) = uVar1;
    FUN_0010823b(lVar3 + 0xc,0x594,param_3);
    sVar4 = strlen(param_3);
    *(int *)(lVar2 + 0x38) = (int)sVar4 + 5;
    FUN_0011a00c(param_1,lVar2,param_4);
  }
  FUN_00119c9c(param_1);
  return;
}



void FUN_0011a374(undefined8 *param_1,undefined8 param_2)

{
  uint16_t uVar1;
  uint uVar2;
  long lVar3;
  long lVar4;
  
  lVar3 = FUN_00110cac(*param_1);
  if (lVar3 != 0) {
    lVar4 = FUN_00119f67(param_1,lVar3);
    uVar1 = htons(3);
    *(uint16_t *)(lVar4 + 8) = uVar1;
    uVar1 = htons((short)*(undefined4 *)((long)param_1 + 0x9c) + 1);
    *(uint16_t *)(lVar4 + 10) = uVar1;
    uVar2 = FUN_00119eab(param_1,*(undefined4 *)((long)param_1 + 0x9c),lVar4 + 0xc,
                         *(undefined2 *)((long)param_1 + 0x14));
    if ((int)uVar2 < 0) {
      FUN_00110e00(lVar3);
      FUN_0011a26e(param_1,1,"File not found",lVar4);
    }
    else {
      *(uint *)(lVar3 + 0x38) = uVar2 + 4;
      FUN_0011a00c(param_1,lVar3,param_2);
      if (uVar2 == *(ushort *)((long)param_1 + 0x14)) {
        FUN_00119c7f(param_1);
      }
      else {
        FUN_00119c9c(param_1);
      }
      *(int *)((long)param_1 + 0x9c) = *(int *)((long)param_1 + 0x9c) + 1;
    }
  }
  return;
}



void FUN_0011a4be(long param_1,undefined8 param_2,long param_3,int param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  long lVar4;
  size_t sVar5;
  undefined8 uVar6;
  char *pcVar7;
  char *pcVar8;
  long in_FS_OFFSET;
  int local_fc;
  uint local_f8;
  uint local_f4;
  uint local_c0 [2];
  undefined8 local_b8 [2];
  undefined local_a8 [152];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_f8 = 0;
  iVar1 = FUN_00119e05(param_1,param_2,param_3);
  if (-1 < iVar1) {
    FUN_00119c9c(param_1 + (long)iVar1 * 0xa8 + 0x6e0);
  }
  iVar1 = FUN_00119cee(param_1,param_2,param_3);
  if (-1 < iVar1) {
    lVar4 = param_1 + (long)iVar1 * 0xa8 + 0x6e0;
    if (*(long *)(param_1 + 0x6d8) == 0) {
      FUN_0011a26e(lVar4,2,"Access violation",param_3);
    }
    else {
      local_fc = 0;
      iVar2 = param_4 + -10;
      sVar5 = strlen(*(char **)(param_1 + 0x6d8));
      uVar6 = g_malloc(sVar5 + 0x202);
      *(undefined8 *)(lVar4 + 8) = uVar6;
      memcpy(*(void **)(lVar4 + 8),*(void **)(param_1 + 0x6d8),sVar5);
      *(undefined *)(sVar5 + *(long *)(lVar4 + 8)) = 0x2f;
      pcVar7 = (char *)(*(long *)(lVar4 + 8) + sVar5 + 1);
      iVar1 = local_fc;
      do {
        local_fc = iVar1;
        if ((0x1ff < local_fc) || (iVar2 <= local_fc)) {
          FUN_0011a26e(lVar4,2,"Access violation",param_3);
          goto LAB_0011abed;
        }
        pcVar7[local_fc] = *(char *)(param_3 + 10 + (long)local_fc);
        iVar1 = local_fc + 1;
      } while (pcVar7[local_fc] != '\0');
      if ((DAT_001231c0 & 8) != 0) {
        g_log("Slirp",0x80,"tftp rrq file: %s",pcVar7);
      }
      if (iVar2 - iVar1 < 6) {
        FUN_0011a26e(lVar4,2,"Access violation",param_3);
      }
      else {
        iVar1 = strcasecmp((char *)(param_3 + iVar1 + 10),"octet");
        if (iVar1 == 0) {
          local_fc = local_fc + 7;
          pcVar8 = strstr(pcVar7,"../");
          if ((pcVar8 == (char *)0x0) && (sVar5 = strlen(pcVar7), pcVar7[sVar5 - 1] != '/')) {
            iVar1 = FUN_00119eab(lVar4,0,0,0);
            if (iVar1 < 0) {
              FUN_0011a26e(lVar4,1,"File not found",param_3);
            }
            else if (*(char *)(param_3 + 10 + (long)(param_4 + -0xb)) == '\0') {
              while ((local_fc < iVar2 && (local_f8 < 2))) {
                pcVar7 = (char *)(param_3 + local_fc + 10);
                sVar5 = strlen(pcVar7);
                iVar1 = local_fc + (int)sVar5 + 1;
                if (iVar2 <= iVar1) {
                  FUN_0011a26e(lVar4,2,"Access violation",param_3);
                  goto LAB_0011abed;
                }
                pcVar8 = (char *)(param_3 + iVar1 + 10);
                sVar5 = strlen(pcVar8);
                local_fc = iVar1 + (int)sVar5 + 1;
                iVar1 = strcasecmp(pcVar7,"tsize");
                if (iVar1 == 0) {
                  local_f4 = atoi(pcVar8);
                  if (local_f4 == 0) {
                    iVar1 = FUN_0011c0b0(*(undefined8 *)(lVar4 + 8),local_a8);
                    if (iVar1 != 0) {
                      FUN_0011a26e(lVar4,1,"File not found",param_3);
                      goto LAB_0011abed;
                    }
                    local_f4 = (uint)local_a8._48_8_;
                  }
                  local_b8[(int)local_f8] = "tsize";
                  local_c0[(int)local_f8] = local_f4;
                  local_f8 = local_f8 + 1;
                }
                else {
                  iVar1 = strcasecmp(pcVar7,"blksize");
                  if ((iVar1 == 0) && (iVar1 = atoi(pcVar8), 0 < iVar1)) {
                    iVar3 = 0x594;
                    if (iVar1 < 0x595) {
                      iVar3 = iVar1;
                    }
                    *(short *)(lVar4 + 0x14) = (short)iVar3;
                    local_b8[(int)local_f8] = "blksize";
                    local_c0[(int)local_f8] = (uint)*(ushort *)(lVar4 + 0x14);
                    local_f8 = local_f8 + 1;
                  }
                }
              }
              if ((int)local_f8 < 1) {
                *(undefined4 *)(lVar4 + 0x9c) = 0;
                FUN_0011a374(lVar4,param_3);
              }
              else {
                if (2 < local_f8) {
                    // WARNING: Subroutine does not return
                  __assert_fail("nb_options <= G_N_ELEMENTS(option_name)",
                                "/home/remnux/Desktop/Thesis-Experiments/Third_Experiment/SAST_With_SRE/CVEs/BUG-2010_Libslirp/Libslirp/src/tftp.c"
                                ,0x19a,"tftp_handle_rrq");
                }
                FUN_0011a112(lVar4,local_b8,local_c0,local_f8,param_3);
              }
            }
            else {
              FUN_0011a26e(lVar4,2,"Access violation",param_3);
            }
          }
          else {
            FUN_0011a26e(lVar4,2,"Access violation",param_3);
          }
        }
        else {
          FUN_0011a26e(lVar4,4,"Unsupported transfer mode",param_3);
        }
      }
    }
  }
LAB_0011abed:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0011ac03(long param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  
  iVar1 = FUN_00119e05(param_1,param_2,param_3);
  if (-1 < iVar1) {
    FUN_0011a374((long)iVar1 * 0xa8 + 0x6e0 + param_1,param_3);
  }
  return;
}



void FUN_0011ac7b(long param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  
  iVar1 = FUN_00119e05(param_1,param_2,param_3);
  if (-1 < iVar1) {
    FUN_00119c9c(param_1 + (long)iVar1 * 0xa8 + 0x6e0);
  }
  return;
}



void FUN_0011acec(undefined8 param_1,long param_2)

{
  long lVar1;
  uint16_t uVar2;
  
  lVar1 = *(long *)(param_2 + 0x30);
  uVar2 = ntohs(*(uint16_t *)(lVar1 + 8));
  if (uVar2 == 5) {
    FUN_0011ac7b(*(undefined8 *)(param_2 + 0x40),param_1,lVar1,*(undefined4 *)(param_2 + 0x38));
  }
  else if (uVar2 < 6) {
    if (uVar2 == 1) {
      FUN_0011a4be(*(undefined8 *)(param_2 + 0x40),param_1,lVar1,*(undefined4 *)(param_2 + 0x38));
    }
    else if (uVar2 == 4) {
      FUN_0011ac03(*(undefined8 *)(param_2 + 0x40),param_1,lVar1,*(undefined4 *)(param_2 + 0x38));
    }
  }
  return;
}



undefined8 FUN_0011ad9c(void *param_1,void *param_2)

{
  int iVar1;
  undefined4 extraout_var;
  
  iVar1 = memcmp(param_1,param_2,0x10);
  return CONCAT71((int7)(CONCAT44(extraout_var,iVar1) >> 8),iVar1 == 0);
}



void FUN_0011adcb(long param_1)

{
  long lVar1;
  undefined8 *puVar2;
  undefined2 *puVar3;
  undefined8 uVar4;
  char cVar5;
  uint16_t uVar6;
  uint16_t uVar7;
  int iVar8;
  uint uVar9;
  int *piVar10;
  char *pcVar11;
  long in_FS_OFFSET;
  long local_98;
  undefined local_78;
  undefined local_77;
  undefined local_76;
  undefined local_75;
  undefined local_74;
  undefined local_73;
  undefined local_72;
  undefined local_71;
  undefined local_70;
  undefined local_6f;
  undefined local_6e;
  undefined local_6d;
  undefined local_6c;
  undefined local_6b;
  undefined local_6a;
  undefined local_69;
  undefined2 local_68;
  undefined2 local_66;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = *(long *)(param_1 + 0x40);
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"udp6_input...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_1);
  }
  if (*(int *)(lVar1 + 0x7c) == 0) {
    puVar2 = *(undefined8 **)(param_1 + 0x30);
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -0x28;
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 0x28;
    puVar3 = *(undefined2 **)(param_1 + 0x30);
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0x28;
    *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0x28;
    iVar8 = FUN_0010d98f(param_1);
    if (iVar8 == 0) {
      uVar6 = ntohs(puVar3[2]);
      uVar9 = (uint)uVar6;
      uVar7 = ntohs(*(uint16_t *)((long)puVar2 + 4));
      if (uVar9 != uVar7) {
        uVar7 = ntohs(*(uint16_t *)((long)puVar2 + 4));
        if (uVar7 < uVar9) goto LAB_0011b55b;
        uVar7 = ntohs(*(uint16_t *)((long)puVar2 + 4));
        FUN_00111173(param_1,uVar9 - uVar7);
        uVar6 = htons(uVar6);
        *(uint16_t *)((long)puVar2 + 4) = uVar6;
      }
      local_48 = *puVar2;
      local_40 = puVar2[1];
      local_38 = puVar2[2];
      local_30 = puVar2[3];
      local_28 = puVar2[4];
      local_68 = 10;
      local_58 = puVar2[2];
      local_60 = puVar2[1];
      local_66 = *puVar3;
      uVar6 = ntohs(puVar3[1]);
      if (uVar6 == 0x223) {
        cVar5 = FUN_0011ad9c(puVar2 + 3,lVar1 + 0x2c);
        if (cVar5 == '\0') {
          local_78 = 0xff;
          local_77 = 2;
          local_76 = 0;
          local_75 = 0;
          local_74 = 0;
          local_73 = 0;
          local_72 = 0;
          local_71 = 0;
          local_70 = 0;
          local_6f = 0;
          local_6e = 0;
          local_6d = 0;
          local_6c = 0;
          local_6b = 1;
          local_6a = 0;
          local_69 = 2;
          cVar5 = FUN_0011ad9c(puVar2 + 3,&local_78);
          if (cVar5 == '\0') goto LAB_0011b155;
        }
        *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 0x28;
        *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -0x28;
        FUN_0011bf60(&local_68,param_1);
        *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0x28;
        *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0x28;
      }
      else {
LAB_0011b155:
        uVar6 = ntohs(puVar3[1]);
        if ((uVar6 == 0x45) && (iVar8 = memcmp(puVar2 + 3,(void *)(lVar1 + 0x2c),0x10), iVar8 == 0))
        {
          *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 0x28;
          *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -0x28;
          FUN_0011acec(&local_68,param_1);
          *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0x28;
          *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0x28;
        }
        else {
          local_98 = FUN_0011367c(lVar1 + 0x520,lVar1 + 0x378,&local_68,0);
          if (local_98 == 0) {
            local_98 = FUN_0011376d(lVar1);
            iVar8 = FUN_0010a0ab(local_98,10);
            if (iVar8 == -1) {
              if ((DAT_001231c0 & 2) != 0) {
                piVar10 = __errno_location();
                pcVar11 = strerror(*piVar10);
                piVar10 = __errno_location();
                g_log("Slirp",0x80," udp6_attach errno = %d-%s",*piVar10,pcVar11);
              }
              FUN_0011385c(local_98);
              goto LAB_0011b55b;
            }
            *(undefined2 *)(local_98 + 200) = 10;
            uVar4 = puVar2[2];
            *(undefined8 *)(local_98 + 0xd0) = puVar2[1];
            *(undefined8 *)(local_98 + 0xd8) = uVar4;
            *(undefined2 *)(local_98 + 0xca) = *puVar3;
          }
          *(undefined2 *)(local_98 + 0x48) = 10;
          uVar4 = puVar2[4];
          *(undefined8 *)(local_98 + 0x50) = puVar2[3];
          *(undefined8 *)(local_98 + 0x58) = uVar4;
          *(undefined2 *)(local_98 + 0x4a) = puVar3[1];
          *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -0x30;
          *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + 0x30;
          iVar8 = FUN_001154c3(local_98,param_1);
          if (iVar8 != -1) {
            FUN_00110e00(*(undefined8 *)(local_98 + 0x30));
            *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0x30;
            *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0x30;
            *puVar2 = local_48;
            puVar2[1] = local_40;
            puVar2[2] = local_38;
            puVar2[3] = local_30;
            puVar2[4] = local_28;
            *(long *)(local_98 + 0x30) = param_1;
            goto LAB_0011b56a;
          }
          *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 0x30;
          *(long *)(param_1 + 0x30) = *(long *)(param_1 + 0x30) + -0x30;
          *puVar2 = local_48;
          puVar2[1] = local_40;
          puVar2[2] = local_38;
          puVar2[3] = local_30;
          puVar2[4] = local_28;
          if ((DAT_001231c0 & 2) != 0) {
            piVar10 = __errno_location();
            pcVar11 = strerror(*piVar10);
            piVar10 = __errno_location();
            g_log("Slirp",0x80,"udp tx errno = %d-%s",*piVar10,pcVar11);
          }
          FUN_00111956(param_1,1,0);
        }
      }
    }
  }
LAB_0011b55b:
  FUN_00110e00(param_1);
LAB_0011b56a:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0011b588(undefined8 param_1,long param_2,long param_3,long param_4)

{
  undefined2 *puVar1;
  long lVar2;
  undefined8 uVar3;
  uint16_t uVar4;
  undefined2 uVar5;
  
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80,"udp6_output...");
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," so = %p",param_1);
  }
  if ((DAT_001231c0 & 1) != 0) {
    g_log("Slirp",0x80," m = %p",param_2);
  }
  *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + -8;
  *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + 8;
  puVar1 = *(undefined2 **)(param_2 + 0x30);
  *(long *)(param_2 + 0x30) = *(long *)(param_2 + 0x30) + -0x28;
  *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + 0x28;
  lVar2 = *(long *)(param_2 + 0x30);
  uVar4 = htons((short)*(undefined4 *)(param_2 + 0x38) - 0x28);
  *(uint16_t *)(lVar2 + 4) = uVar4;
  *(undefined *)(lVar2 + 6) = 0x11;
  uVar3 = *(undefined8 *)(param_3 + 0x10);
  *(undefined8 *)(lVar2 + 8) = *(undefined8 *)(param_3 + 8);
  *(undefined8 *)(lVar2 + 0x10) = uVar3;
  uVar3 = *(undefined8 *)(param_4 + 0x10);
  *(undefined8 *)(lVar2 + 0x18) = *(undefined8 *)(param_4 + 8);
  *(undefined8 *)(lVar2 + 0x20) = uVar3;
  *puVar1 = *(undefined2 *)(param_3 + 2);
  puVar1[1] = *(undefined2 *)(param_4 + 2);
  puVar1[2] = *(undefined2 *)(lVar2 + 4);
  puVar1[3] = 0;
  uVar5 = FUN_0010d98f(param_2);
  puVar1[3] = uVar5;
  if (puVar1[3] == 0) {
    puVar1[3] = 0xffff;
  }
  FUN_00107b40(param_1,param_2,0);
  return;
}



undefined8 FUN_0011b76c(long param_1,undefined *param_2,int param_3,long *param_4)

{
  ushort uVar1;
  short sVar2;
  uint uVar3;
  int local_2c;
  undefined *local_28;
  int local_18;
  
  local_2c = param_3;
  local_28 = param_2;
  do {
    if (local_2c < 5) {
      return 0;
    }
    uVar1 = CONCAT11(*local_28,local_28[1]);
    uVar3 = (uint)CONCAT11(local_28[2],local_28[3]);
    if (local_2c <= (int)(uVar3 + 3)) {
      (**(code **)(*(long *)(param_1 + 0x1768) + 8))
                ("Guest sent bad DHCPv6 packet!",*(undefined8 *)(param_1 + 6000));
      return 0xfffffff9;
    }
    if (uVar1 == 6) {
      if ((local_28[3] & 1) != 0) {
        return 0xffffffea;
      }
      for (local_18 = 0; local_18 < (int)uVar3; local_18 = local_18 + 2) {
        sVar2 = CONCAT11(local_28[local_18 + 4],local_28[(long)(local_18 + 4) + 1]);
        if (sVar2 == 0x17) {
          *(undefined *)((long)param_4 + 0xc) = 1;
        }
        else if (sVar2 == 0x3b) {
          *(undefined *)((long)param_4 + 0xd) = 1;
        }
        else if ((DAT_001231c0 & 2) != 0) {
          g_log("Slirp",0x80,"dhcpv6: Unsupported option request %d",sVar2);
        }
      }
    }
    else {
      if (uVar1 < 7) {
        if (uVar1 == 1) {
          if (0x100 < uVar3) {
            return 0xfffffff9;
          }
          *param_4 = (long)(local_28 + 4);
          *(uint *)(param_4 + 1) = uVar3;
          goto LAB_0011b95b;
        }
        if (uVar1 == 5) {
          return 0xffffffea;
        }
      }
      if ((DAT_001231c0 & 2) != 0) {
        g_log("Slirp",0x80,"dhcpv6 info req: Unsupported option %d, len=%d",uVar1,uVar3);
      }
    }
LAB_0011b95b:
    local_28 = local_28 + (long)(int)uVar3 + 4;
    local_2c = local_2c - (uVar3 + 4);
  } while( true );
}



void FUN_0011b982(long param_1,long param_2,undefined4 param_3,undefined8 param_4,undefined4 param_5
                 )

{
  long lVar1;
  undefined8 uVar2;
  int iVar3;
  long lVar4;
  long in_FS_OFFSET;
  undefined *local_b0;
  void *local_98;
  undefined8 local_90;
  undefined local_88 [2];
  undefined2 local_86;
  undefined8 local_80;
  undefined8 local_78;
  undefined local_68 [2];
  undefined2 local_66;
  undefined8 local_60;
  undefined8 local_58;
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  local_98 = (void *)0x0;
  local_90 = 0;
  iVar3 = FUN_0011b76c(param_1,param_4,param_5,&local_98);
  if ((-1 < iVar3) && (lVar4 = FUN_00110cac(param_1), lVar4 != 0)) {
    memset(*(void **)(lVar4 + 0x30),0,(long)*(int *)(lVar4 + 0x24));
    *(long *)(lVar4 + 0x30) = *(long *)(lVar4 + 0x30) + 0x10;
    lVar1 = *(long *)(lVar4 + 0x30);
    *(undefined *)(lVar1 + 0x30) = 7;
    *(char *)(lVar1 + 0x31) = (char)((uint)param_3 >> 0x10);
    *(char *)(lVar1 + 0x32) = (char)((uint)param_3 >> 8);
    local_b0 = (undefined *)(lVar1 + 0x34);
    *(char *)(lVar1 + 0x33) = (char)param_3;
    if (local_98 != (void *)0x0) {
      *local_b0 = 0;
      *(undefined *)(lVar1 + 0x35) = 1;
      *(char *)(lVar1 + 0x36) = (char)((ulong)local_90 >> 8);
      *(char *)(lVar1 + 0x37) = (char)local_90;
      memcpy((void *)(lVar1 + 0x38),local_98,(long)(int)local_90);
      local_b0 = (undefined *)(lVar1 + 0x38 + (long)(int)local_90);
    }
    if (local_90._4_1_ != '\0') {
      *local_b0 = 0;
      local_b0[1] = 0x17;
      local_b0[2] = 0;
      local_b0[3] = 0x10;
      uVar2 = *(undefined8 *)(param_1 + 0x4c);
      *(undefined8 *)(local_b0 + 4) = *(undefined8 *)(param_1 + 0x44);
      *(undefined8 *)(local_b0 + 0xc) = uVar2;
      local_b0 = local_b0 + 0x14;
    }
    if (local_90._5_1_ != '\0') {
      *local_b0 = 0;
      local_b0[1] = 0x3b;
      iVar3 = FUN_0010831e(local_b0 + 4,
                           (long)(((int)*(undefined8 *)(lVar4 + 0x30) + *(int *)(param_1 + 0x88)) -
                                 ((int)(local_b0 + 2) + 2)),
                           "tftp://[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]/%s"
                           ,*(undefined *)(param_1 + 0x2c),*(undefined *)(param_1 + 0x2d),
                           *(undefined *)(param_1 + 0x2e),*(undefined *)(param_1 + 0x2f),
                           *(undefined *)(param_1 + 0x30),*(undefined *)(param_1 + 0x31),
                           *(undefined *)(param_1 + 0x32),*(undefined *)(param_1 + 0x33),
                           *(undefined *)(param_1 + 0x34),*(undefined *)(param_1 + 0x35),
                           *(undefined *)(param_1 + 0x36),*(undefined *)(param_1 + 0x37),
                           *(undefined *)(param_1 + 0x38),*(undefined *)(param_1 + 0x39),
                           *(undefined *)(param_1 + 0x3a),*(undefined *)(param_1 + 0x3b),
                           *(undefined8 *)(param_1 + 0x1a0));
      local_b0[2] = (char)((uint)iVar3 >> 8);
      local_b0[3] = (char)iVar3;
      local_b0 = local_b0 + (long)iVar3 + 4;
    }
    local_78 = *(undefined8 *)(param_1 + 0x34);
    local_80 = *(undefined8 *)(param_1 + 0x2c);
    local_86 = 0x223;
    local_58 = *(undefined8 *)(param_2 + 0x10);
    local_60 = *(undefined8 *)(param_2 + 8);
    local_66 = *(undefined2 *)(param_2 + 2);
    *(long *)(lVar4 + 0x30) = *(long *)(lVar4 + 0x30) + 0x30;
    *(int *)(lVar4 + 0x38) = (int)local_b0 - (int)*(undefined8 *)(lVar4 + 0x30);
    FUN_0011b588(0,lVar4,local_88,local_68);
  }
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0011bf60(undefined8 param_1,long param_2)

{
  int iVar1;
  long lVar2;
  uint32_t uVar3;
  uint32_t *puVar4;
  
  lVar2 = *(long *)(param_2 + 0x30);
  puVar4 = (uint32_t *)(lVar2 + 8);
  iVar1 = *(int *)(param_2 + 0x38);
  if (3 < iVar1 + -8) {
    uVar3 = ntohl(*puVar4);
    if (*(char *)puVar4 == '\v') {
      FUN_0011b982(*(undefined8 *)(param_2 + 0x40),param_1,uVar3 & 0xffffff,lVar2 + 0xc,iVar1 + -0xc
                  );
    }
    else if ((DAT_001231c0 & 2) != 0) {
      g_log("Slirp",0x80,"dhcpv6_input: Unsupported message type 0x%x",*(char *)puVar4);
    }
  }
  return;
}



void FUN_0011c030(undefined4 param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  
  _DT_INIT();
  if (true) {
    lVar1 = 0;
    do {
      (*(code *)(&__DT_INIT_ARRAY)[lVar1])(param_1,param_2,param_3);
      lVar1 = lVar1 + 1;
    } while (lVar1 != 1);
  }
  return;
}



void FUN_0011c0a0(void)

{
  return;
}



void FUN_0011c0b0(char *param_1,stat *param_2)

{
  __xstat(1,param_1,param_2);
  return;
}



void _DT_FINI(void)

{
  return;
}


