#[nowarn(dead_code)]

use std::libc::*;
pub type __int128_t = c_void;
pub type __uint128_t = c_void;
pub type __builtin_va_list = [__va_list_tag, ..1u];
pub type __u_char = c_uchar;
pub type __u_short = c_ushort;
pub type __u_int = c_uint;
pub type __u_long = c_ulong;
pub type __int8_t = c_schar;
pub type __uint8_t = c_uchar;
pub type __int16_t = c_short;
pub type __uint16_t = c_ushort;
pub type __int32_t = c_int;
pub type __uint32_t = c_uint;
pub type __int64_t = c_long;
pub type __uint64_t = c_ulong;
pub type __quad_t = c_long;
pub type __u_quad_t = c_ulong;
pub type __dev_t = c_ulong;
pub type __uid_t = c_uint;
pub type __gid_t = c_uint;
pub type __ino_t = c_ulong;
pub type __ino64_t = c_ulong;
pub type __mode_t = c_uint;
pub type __nlink_t = c_ulong;
pub type __off_t = c_long;
pub type __off64_t = c_long;
pub type __pid_t = c_int;
pub struct __fsid_t {
    __val: [c_int, ..2u],
}
pub type __clock_t = c_long;
pub type __rlim_t = c_ulong;
pub type __rlim64_t = c_ulong;
pub type __id_t = c_uint;
pub type __time_t = c_long;
pub type __useconds_t = c_uint;
pub type __suseconds_t = c_long;
pub type __daddr_t = c_int;
pub type __key_t = c_int;
pub type __clockid_t = c_int;
pub type __timer_t = *mut c_void;
pub type __blksize_t = c_long;
pub type __blkcnt_t = c_long;
pub type __blkcnt64_t = c_long;
pub type __fsblkcnt_t = c_ulong;
pub type __fsblkcnt64_t = c_ulong;
pub type __fsfilcnt_t = c_ulong;
pub type __fsfilcnt64_t = c_ulong;
pub type __fsword_t = c_long;
pub type __ssize_t = c_long;
pub type __syscall_slong_t = c_long;
pub type __syscall_ulong_t = c_ulong;
pub type __loff_t = __off64_t;
pub type __qaddr_t = *mut __quad_t;
pub type __caddr_t = *mut c_schar;
pub type __intptr_t = c_long;
pub type __socklen_t = c_uint;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type quad_t = __quad_t;
pub type u_quad_t = __u_quad_t;
pub type fsid_t = __fsid_t;
pub type loff_t = __loff_t;
pub type ino_t = __ino_t;
pub type dev_t = __dev_t;
pub type gid_t = __gid_t;
pub type mode_t = __mode_t;
pub type nlink_t = __nlink_t;
pub type uid_t = __uid_t;
pub type off_t = __off_t;
pub type pid_t = __pid_t;
pub type id_t = __id_t;
pub type ssize_t = __ssize_t;
pub type daddr_t = __daddr_t;
pub type caddr_t = __caddr_t;
pub type key_t = __key_t;
pub type clock_t = __clock_t;
pub type time_t = __time_t;
pub type clockid_t = __clockid_t;
pub type timer_t = __timer_t;
pub type ptrdiff_t = c_long;
pub type size_t = c_ulong;
pub type wchar_t = c_int;
pub type ulong = c_ulong;
pub type ushort = c_ushort;
pub type _uint = c_uint;
pub type int8_t = c_schar;
pub type int16_t = c_short;
pub type int32_t = c_int;
pub type int64_t = c_long;
pub type u_int8_t = c_uchar;
pub type u_int16_t = c_ushort;
pub type u_int32_t = c_uint;
pub type u_int64_t = c_ulong;
pub type register_t = c_long;
pub type __sig_atomic_t = c_int;
pub struct __sigset_t {
    __val: [c_ulong, ..16u],
}
pub type sigset_t = __sigset_t;
pub struct Struct_timespec {
    tv_sec: __time_t,
    tv_nsec: __syscall_slong_t,
}
pub struct Struct_timeval {
    tv_sec: __time_t,
    tv_usec: __suseconds_t,
}
pub type suseconds_t = __suseconds_t;
pub type __fd_mask = c_long;
pub struct fd_set {
    __fds_bits: [__fd_mask, ..16u],
}
pub type fd_mask = __fd_mask;
pub type blksize_t = __blksize_t;
pub type blkcnt_t = __blkcnt_t;
pub type fsblkcnt_t = __fsblkcnt_t;
pub type fsfilcnt_t = __fsfilcnt_t;
pub type pthread_t = c_ulong;
pub struct Union_pthread_attr_t {
    data: [u64, ..7u],
}
impl Union_pthread_attr_t {
    pub fn __size(&mut self) -> *mut [c_schar, ..56u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_long {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub type pthread_attr_t = Union_pthread_attr_t;
pub struct Struct___pthread_internal_list {
    __prev: *mut Struct___pthread_internal_list,
    __next: *mut Struct___pthread_internal_list,
}
pub type __pthread_list_t = Struct___pthread_internal_list;
pub struct Struct___pthread_mutex_s {
    __lock: c_int,
    __count: c_uint,
    __owner: c_int,
    __nusers: c_uint,
    __kind: c_int,
    __spins: c_short,
    __elision: c_short,
    __list: __pthread_list_t,
}
pub struct pthread_mutex_t {
    data: [u64, ..5u],
}
impl pthread_mutex_t {
    pub fn __data(&mut self) -> *mut Struct___pthread_mutex_s {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __size(&mut self) -> *mut [c_schar, ..40u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_long {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub struct pthread_mutexattr_t {
    data: [u32, ..1u],
}
impl pthread_mutexattr_t {
    pub fn __size(&mut self) -> *mut [c_schar, ..4u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_int {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub struct Struct_Unnamed1 {
    __lock: c_int,
    __futex: c_uint,
    __total_seq: c_ulonglong,
    __wakeup_seq: c_ulonglong,
    __woken_seq: c_ulonglong,
    __mutex: *mut c_void,
    __nwaiters: c_uint,
    __broadcast_seq: c_uint,
}
pub struct pthread_cond_t {
    data: [u64, ..6u],
}
impl pthread_cond_t {
    pub fn __data(&mut self) -> *mut Struct_Unnamed1 {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __size(&mut self) -> *mut [c_schar, ..48u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_longlong {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub struct pthread_condattr_t {
    data: [u32, ..1u],
}
impl pthread_condattr_t {
    pub fn __size(&mut self) -> *mut [c_schar, ..4u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_int {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub type pthread_key_t = c_uint;
pub type pthread_once_t = c_int;
pub struct Struct_Unnamed2 {
    __lock: c_int,
    __nr_readers: c_uint,
    __readers_wakeup: c_uint,
    __writer_wakeup: c_uint,
    __nr_readers_queued: c_uint,
    __nr_writers_queued: c_uint,
    __writer: c_int,
    __shared: c_int,
    __pad1: c_ulong,
    __pad2: c_ulong,
    __flags: c_uint,
}
pub struct pthread_rwlock_t {
    data: [u64, ..7u],
}
impl pthread_rwlock_t {
    pub fn __data(&mut self) -> *mut Struct_Unnamed2 {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __size(&mut self) -> *mut [c_schar, ..56u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_long {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub struct pthread_rwlockattr_t {
    data: [u64, ..1u],
}
impl pthread_rwlockattr_t {
    pub fn __size(&mut self) -> *mut [c_schar, ..8u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_long {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub type pthread_spinlock_t = c_int;
pub struct pthread_barrier_t {
    data: [u64, ..4u],
}
impl pthread_barrier_t {
    pub fn __size(&mut self) -> *mut [c_schar, ..32u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_long {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub struct pthread_barrierattr_t {
    data: [u32, ..1u],
}
impl pthread_barrierattr_t {
    pub fn __size(&mut self) -> *mut [c_schar, ..4u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __align(&mut self) -> *mut c_int {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub struct Struct_timezone {
    tz_minuteswest: c_int,
    tz_dsttime: c_int,
}
pub type __timezone_ptr_t = *mut Struct_timezone;
pub type Enum___itimer_which = c_uint;
pub static ITIMER_REAL: c_uint = 0;
pub static ITIMER_VIRTUAL: c_uint = 1;
pub static ITIMER_PROF: c_uint = 2;
pub struct Struct_itimerval {
    it_interval: Struct_timeval,
    it_value: Struct_timeval,
}
pub type __itimer_which_t = c_int;
pub type bpf_int32 = c_int;
pub type bpf_u_int32 = u_int;
pub struct Struct_bpf_program {
    bf_len: u_int,
    bf_insns: *mut Struct_bpf_insn,
}
pub struct Struct_bpf_insn {
    code: u_short,
    jt: u_char,
    jf: u_char,
    k: bpf_u_int32,
}
pub type FILE = Struct__IO_FILE;
pub type __FILE = Struct__IO_FILE;
pub struct Union_Unnamed3 {
    data: [u32, ..1u],
}
impl Union_Unnamed3 {
    pub fn __wch(&mut self) -> *mut c_uint {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
    pub fn __wchb(&mut self) -> *mut [c_schar, ..4u] {
        unsafe { ::std::cast::transmute(::std::ptr::to_mut_unsafe_ptr(self)) }
    }
}
pub struct __mbstate_t {
    __count: c_int,
    __value: Union_Unnamed3,
}
pub struct _G_fpos_t {
    __pos: __off_t,
    __state: __mbstate_t,
}
pub struct _G_fpos64_t {
    __pos: __off64_t,
    __state: __mbstate_t,
}
pub type va_list = __builtin_va_list;
pub type __gnuc_va_list = __builtin_va_list;
pub type Struct__IO_jump_t = c_void;
pub type _IO_lock_t = c_void;
pub struct Struct__IO_marker {
    _next: *mut Struct__IO_marker,
    _sbuf: *mut Struct__IO_FILE,
    _pos: c_int,
}
pub type Enum___codecvt_result = c_uint;
pub static __codecvt_ok: c_uint = 0;
pub static __codecvt_partial: c_uint = 1;
pub static __codecvt_error: c_uint = 2;
pub static __codecvt_noconv: c_uint = 3;
pub struct Struct__IO_FILE {
    _flags: c_int,
    _IO_read_ptr: *mut c_schar,
    _IO_read_end: *mut c_schar,
    _IO_read_base: *mut c_schar,
    _IO_write_base: *mut c_schar,
    _IO_write_ptr: *mut c_schar,
    _IO_write_end: *mut c_schar,
    _IO_buf_base: *mut c_schar,
    _IO_buf_end: *mut c_schar,
    _IO_save_base: *mut c_schar,
    _IO_backup_base: *mut c_schar,
    _IO_save_end: *mut c_schar,
    _markers: *mut Struct__IO_marker,
    _chain: *mut Struct__IO_FILE,
    _fileno: c_int,
    _flags2: c_int,
    _old_offset: __off_t,
    _cur_column: c_ushort,
    _vtable_offset: c_schar,
    _shortbuf: [c_schar, ..1u],
    _lock: *mut _IO_lock_t,
    _offset: __off64_t,
    __pad1: *mut c_void,
    __pad2: *mut c_void,
    __pad3: *mut c_void,
    __pad4: *mut c_void,
    __pad5: size_t,
    _mode: c_int,
    _unused2: [c_schar, ..20u],
}
pub type _IO_FILE = Struct__IO_FILE;
pub type Struct__IO_FILE_plus = c_void;
pub type __io_read_fn = c_void;
pub type __io_write_fn = c_void;
pub type __io_seek_fn = c_void;
pub type __io_close_fn = c_void;
pub type fpos_t = _G_fpos_t;
pub type Struct_pcap = c_void;
pub type pcap_t = Struct_pcap;
pub type Struct_pcap_dumper = c_void;
pub type pcap_dumper_t = Struct_pcap_dumper;
pub type pcap_if_t = Struct_pcap_if;
pub type pcap_addr_t = Struct_pcap_addr;
pub struct Struct_pcap_file_header {
    magic: bpf_u_int32,
    version_major: u_short,
    version_minor: u_short,
    thiszone: bpf_int32,
    sigfigs: bpf_u_int32,
    snaplen: bpf_u_int32,
    linktype: bpf_u_int32,
}
pub type pcap_direction_t = c_uint;
pub static PCAP_D_INOUT: c_uint = 0;
pub static PCAP_D_IN: c_uint = 1;
pub static PCAP_D_OUT: c_uint = 2;
pub struct Struct_pcap_pkthdr {
    ts: Struct_timeval,
    caplen: bpf_u_int32,
    len: bpf_u_int32,
}
pub struct Struct_pcap_stat {
    ps_recv: u_int,
    ps_drop: u_int,
    ps_ifdrop: u_int,
}
pub struct Struct_pcap_if {
    next: *mut Struct_pcap_if,
    name: *mut c_schar,
    description: *mut c_schar,
    addresses: *mut Struct_pcap_addr,
    flags: bpf_u_int32,
}
pub struct Struct_pcap_addr {
    next: *mut Struct_pcap_addr,
    addr: *mut Struct_sockaddr,
    netmask: *mut Struct_sockaddr,
    broadaddr: *mut Struct_sockaddr,
    dstaddr: *mut Struct_sockaddr,
}
pub type Struct_sockaddr = c_void;
pub type pcap_handler =
    extern "C" fn
        (arg1: *mut u_char, arg2: *Struct_pcap_pkthdr, arg3: *u_char);
pub type __va_list_tag = Struct___va_list_tag;
pub struct Struct___va_list_tag {
    gp_offset: c_uint,
    fp_offset: c_uint,
    overflow_arg_area: *mut c_void,
    reg_save_area: *mut c_void,
}
#[link(name = "pcap", vers="0.0.1")]
extern "C" {
    pub static mut _IO_2_1_stdin_: Struct__IO_FILE_plus;
    pub static mut _IO_2_1_stdout_: Struct__IO_FILE_plus;
    pub static mut _IO_2_1_stderr_: Struct__IO_FILE_plus;
    pub static mut stdin: *mut Struct__IO_FILE;
    pub static mut stdout: *mut Struct__IO_FILE;
    pub static mut stderr: *mut Struct__IO_FILE;
    pub static mut sys_nerr: c_int;
    pub static mut sys_errlist: c_void;
    pub fn select(__nfds: c_int, __readfds: *mut fd_set,
                  __writefds: *mut fd_set, __exceptfds: *mut fd_set,
                  __timeout: *mut Struct_timeval) -> c_int;
    pub fn pselect(__nfds: c_int, __readfds: *mut fd_set,
                   __writefds: *mut fd_set, __exceptfds: *mut fd_set,
                   __timeout: *Struct_timespec, __sigmask: *__sigset_t) ->
     c_int;
    pub fn gnu_dev_major(__dev: c_ulonglong) -> c_uint;
    pub fn gnu_dev_minor(__dev: c_ulonglong) -> c_uint;
    pub fn gnu_dev_makedev(__major: c_uint, __minor: c_uint) -> c_ulonglong;
    pub fn gettimeofday(__tv: *mut Struct_timeval, __tz: __timezone_ptr_t) ->
     c_int;
    pub fn settimeofday(__tv: *Struct_timeval, __tz: *Struct_timezone) ->
     c_int;
    pub fn adjtime(__delta: *Struct_timeval, __olddelta: *mut Struct_timeval)
     -> c_int;
    pub fn getitimer(__which: __itimer_which_t,
                     __value: *mut Struct_itimerval) -> c_int;
    pub fn setitimer(__which: __itimer_which_t, __new: *Struct_itimerval,
                     __old: *mut Struct_itimerval) -> c_int;
    pub fn utimes(__file: *c_schar, __tvp: [Struct_timeval, ..2u]) -> c_int;
    pub fn lutimes(__file: *c_schar, __tvp: [Struct_timeval, ..2u]) -> c_int;
    pub fn futimes(__fd: c_int, __tvp: [Struct_timeval, ..2u]) -> c_int;
    pub fn bpf_validate(arg1: *Struct_bpf_insn, arg2: c_int) -> c_int;
    pub fn bpf_filter(arg1: *Struct_bpf_insn, arg2: *u_char, arg3: u_int,
                      arg4: u_int) -> u_int;
    pub fn __underflow(arg1: *mut _IO_FILE) -> c_int;
    pub fn __uflow(arg1: *mut _IO_FILE) -> c_int;
    pub fn __overflow(arg1: *mut _IO_FILE, arg2: c_int) -> c_int;
    pub fn _IO_getc(__fp: *mut _IO_FILE) -> c_int;
    pub fn _IO_putc(__c: c_int, __fp: *mut _IO_FILE) -> c_int;
    pub fn _IO_feof(__fp: *mut _IO_FILE) -> c_int;
    pub fn _IO_ferror(__fp: *mut _IO_FILE) -> c_int;
    pub fn _IO_peekc_locked(__fp: *mut _IO_FILE) -> c_int;
    pub fn _IO_flockfile(arg1: *mut _IO_FILE);
    pub fn _IO_funlockfile(arg1: *mut _IO_FILE);
    pub fn _IO_ftrylockfile(arg1: *mut _IO_FILE) -> c_int;
    pub fn _IO_vfscanf(arg1: *mut _IO_FILE, arg2: *c_schar,
                       arg3: __gnuc_va_list, arg4: *mut c_int) -> c_int;
    pub fn _IO_vfprintf(arg1: *mut _IO_FILE, arg2: *c_schar,
                        arg3: __gnuc_va_list) -> c_int;
    pub fn _IO_padn(arg1: *mut _IO_FILE, arg2: c_int, arg3: __ssize_t) ->
     __ssize_t;
    pub fn _IO_sgetn(arg1: *mut _IO_FILE, arg2: *mut c_void, arg3: size_t) ->
     size_t;
    pub fn _IO_seekoff(arg1: *mut _IO_FILE, arg2: __off64_t, arg3: c_int,
                       arg4: c_int) -> __off64_t;
    pub fn _IO_seekpos(arg1: *mut _IO_FILE, arg2: __off64_t, arg3: c_int) ->
     __off64_t;
    pub fn _IO_free_backup_area(arg1: *mut _IO_FILE);
    pub fn remove(__filename: *c_schar) -> c_int;
    pub fn rename(__old: *c_schar, __new: *c_schar) -> c_int;
    pub fn renameat(__oldfd: c_int, __old: *c_schar, __newfd: c_int,
                    __new: *c_schar) -> c_int;
    pub fn tmpfile() -> *mut FILE;
    pub fn tmpnam(__s: *mut c_schar) -> *mut c_schar;
    pub fn tmpnam_r(__s: *mut c_schar) -> *mut c_schar;
    pub fn tempnam(__dir: *c_schar, __pfx: *c_schar) -> *mut c_schar;
    pub fn fclose(__stream: *mut FILE) -> c_int;
    pub fn fflush(__stream: *mut FILE) -> c_int;
    pub fn fflush_unlocked(__stream: *mut FILE) -> c_int;
    pub fn fopen(__filename: *c_schar, __modes: *c_schar) -> *mut FILE;
    pub fn freopen(__filename: *c_schar, __modes: *c_schar,
                   __stream: *mut FILE) -> *mut FILE;
    pub fn fdopen(__fd: c_int, __modes: *c_schar) -> *mut FILE;
    pub fn fmemopen(__s: *mut c_void, __len: size_t, __modes: *c_schar) ->
     *mut FILE;
    pub fn open_memstream(__bufloc: *mut *mut c_schar, __sizeloc: *mut size_t)
     -> *mut FILE;
    pub fn setbuf(__stream: *mut FILE, __buf: *mut c_schar);
    pub fn setvbuf(__stream: *mut FILE, __buf: *mut c_schar, __modes: c_int,
                   __n: size_t) -> c_int;
    pub fn setbuffer(__stream: *mut FILE, __buf: *mut c_schar,
                     __size: size_t);
    pub fn setlinebuf(__stream: *mut FILE);
    pub fn fprintf(__stream: *mut FILE, __format: *c_schar, ...) -> c_int;
    pub fn printf(__format: *c_schar, ...) -> c_int;
    pub fn sprintf(__s: *mut c_schar, __format: *c_schar, ...) -> c_int;
    pub fn vfprintf(__s: *mut FILE, __format: *c_schar, __arg: __gnuc_va_list)
     -> c_int;
    pub fn vprintf(__format: *c_schar, __arg: __gnuc_va_list) -> c_int;
    pub fn vsprintf(__s: *mut c_schar, __format: *c_schar,
                    __arg: __gnuc_va_list) -> c_int;
    pub fn snprintf(__s: *mut c_schar, __maxlen: size_t,
                    __format: *c_schar, ...) -> c_int;
    pub fn vsnprintf(__s: *mut c_schar, __maxlen: size_t, __format: *c_schar,
                     __arg: __gnuc_va_list) -> c_int;
    pub fn vdprintf(__fd: c_int, __fmt: *c_schar, __arg: __gnuc_va_list) ->
     c_int;
    pub fn dprintf(__fd: c_int, __fmt: *c_schar, ...) -> c_int;
    pub fn fscanf(__stream: *mut FILE, __format: *c_schar, ...) -> c_int;
    pub fn scanf(__format: *c_schar, ...) -> c_int;
    pub fn sscanf(__s: *c_schar, __format: *c_schar, ...) -> c_int;
    pub fn vfscanf(__s: *mut FILE, __format: *c_schar, __arg: __gnuc_va_list)
     -> c_int;
    pub fn vscanf(__format: *c_schar, __arg: __gnuc_va_list) -> c_int;
    pub fn vsscanf(__s: *c_schar, __format: *c_schar, __arg: __gnuc_va_list)
     -> c_int;
    pub fn fgetc(__stream: *mut FILE) -> c_int;
    pub fn getc(__stream: *mut FILE) -> c_int;
    pub fn getchar() -> c_int;
    pub fn getc_unlocked(__stream: *mut FILE) -> c_int;
    pub fn getchar_unlocked() -> c_int;
    pub fn fgetc_unlocked(__stream: *mut FILE) -> c_int;
    pub fn fputc(__c: c_int, __stream: *mut FILE) -> c_int;
    pub fn putc(__c: c_int, __stream: *mut FILE) -> c_int;
    pub fn putchar(__c: c_int) -> c_int;
    pub fn fputc_unlocked(__c: c_int, __stream: *mut FILE) -> c_int;
    pub fn putc_unlocked(__c: c_int, __stream: *mut FILE) -> c_int;
    pub fn putchar_unlocked(__c: c_int) -> c_int;
    pub fn getw(__stream: *mut FILE) -> c_int;
    pub fn putw(__w: c_int, __stream: *mut FILE) -> c_int;
    pub fn fgets(__s: *mut c_schar, __n: c_int, __stream: *mut FILE) ->
     *mut c_schar;
    pub fn gets(__s: *mut c_schar) -> *mut c_schar;
    pub fn __getdelim(__lineptr: *mut *mut c_schar, __n: *mut size_t,
                      __delimiter: c_int, __stream: *mut FILE) -> __ssize_t;
    pub fn getdelim(__lineptr: *mut *mut c_schar, __n: *mut size_t,
                    __delimiter: c_int, __stream: *mut FILE) -> __ssize_t;
    pub fn getline(__lineptr: *mut *mut c_schar, __n: *mut size_t,
                   __stream: *mut FILE) -> __ssize_t;
    pub fn fputs(__s: *c_schar, __stream: *mut FILE) -> c_int;
    pub fn puts(__s: *c_schar) -> c_int;
    pub fn ungetc(__c: c_int, __stream: *mut FILE) -> c_int;
    pub fn fread(__ptr: *mut c_void, __size: size_t, __n: size_t,
                 __stream: *mut FILE) -> size_t;
    pub fn fwrite(__ptr: *c_void, __size: size_t, __n: size_t, __s: *mut FILE)
     -> size_t;
    pub fn fread_unlocked(__ptr: *mut c_void, __size: size_t, __n: size_t,
                          __stream: *mut FILE) -> size_t;
    pub fn fwrite_unlocked(__ptr: *c_void, __size: size_t, __n: size_t,
                           __stream: *mut FILE) -> size_t;
    pub fn fseek(__stream: *mut FILE, __off: c_long, __whence: c_int) ->
     c_int;
    pub fn ftell(__stream: *mut FILE) -> c_long;
    pub fn rewind(__stream: *mut FILE);
    pub fn fseeko(__stream: *mut FILE, __off: __off_t, __whence: c_int) ->
     c_int;
    pub fn ftello(__stream: *mut FILE) -> __off_t;
    pub fn fgetpos(__stream: *mut FILE, __pos: *mut fpos_t) -> c_int;
    pub fn fsetpos(__stream: *mut FILE, __pos: *fpos_t) -> c_int;
    pub fn clearerr(__stream: *mut FILE);
    pub fn feof(__stream: *mut FILE) -> c_int;
    pub fn ferror(__stream: *mut FILE) -> c_int;
    pub fn clearerr_unlocked(__stream: *mut FILE);
    pub fn feof_unlocked(__stream: *mut FILE) -> c_int;
    pub fn ferror_unlocked(__stream: *mut FILE) -> c_int;
    pub fn perror(__s: *c_schar);
    pub fn fileno(__stream: *mut FILE) -> c_int;
    pub fn fileno_unlocked(__stream: *mut FILE) -> c_int;
    pub fn popen(__command: *c_schar, __modes: *c_schar) -> *mut FILE;
    pub fn pclose(__stream: *mut FILE) -> c_int;
    pub fn ctermid(__s: *mut c_schar) -> *mut c_schar;
    pub fn flockfile(__stream: *mut FILE);
    pub fn ftrylockfile(__stream: *mut FILE) -> c_int;
    pub fn funlockfile(__stream: *mut FILE);
    pub fn pcap_lookupdev(arg1: *mut c_schar) -> *mut c_schar;
    pub fn pcap_lookupnet(arg1: *c_schar, arg2: *mut bpf_u_int32,
                          arg3: *mut bpf_u_int32, arg4: *mut c_schar) ->
     c_int;
    pub fn pcap_create(arg1: *c_schar, arg2: *mut c_schar) -> *mut pcap_t;
    pub fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_promisc(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_set_rfmon(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_timeout(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_tstamp_type(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_tstamp_precision(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_activate(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_list_tstamp_types(arg1: *mut pcap_t, arg2: *mut *mut c_int) ->
     c_int;
    pub fn pcap_free_tstamp_types(arg1: *mut c_int);
    pub fn pcap_tstamp_type_name_to_val(arg1: *c_schar) -> c_int;
    pub fn pcap_tstamp_type_val_to_name(arg1: c_int) -> *c_schar;
    pub fn pcap_tstamp_type_val_to_description(arg1: c_int) -> *c_schar;
    pub fn pcap_open_live(arg1: *c_schar, arg2: c_int, arg3: c_int,
                          arg4: c_int, arg5: *mut c_schar) -> *mut pcap_t;
    pub fn pcap_open_dead(arg1: c_int, arg2: c_int) -> *mut pcap_t;
    pub fn pcap_open_dead_with_tstamp_precision(arg1: c_int, arg2: c_int,
                                                arg3: u_int) -> *mut pcap_t;
    pub fn pcap_open_offline_with_tstamp_precision(arg1: *c_schar,
                                                   arg2: u_int,
                                                   arg3: *mut c_schar) ->
     *mut pcap_t;
    pub fn pcap_open_offline(arg1: *c_schar, arg2: *mut c_schar) ->
     *mut pcap_t;
    pub fn pcap_fopen_offline_with_tstamp_precision(arg1: *mut FILE,
                                                    arg2: u_int,
                                                    arg3: *mut c_schar) ->
     *mut pcap_t;
    pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut c_schar) ->
     *mut pcap_t;
    pub fn pcap_close(arg1: *mut pcap_t);
    pub fn pcap_loop(arg1: *mut pcap_t, arg2: c_int, arg3: pcap_handler,
                     arg4: *mut u_char) -> c_int;
    pub fn pcap_dispatch(arg1: *mut pcap_t, arg2: c_int, arg3: pcap_handler,
                         arg4: *mut u_char) -> c_int;
    pub fn pcap_next(arg1: *mut pcap_t, arg2: *mut Struct_pcap_pkthdr) ->
     *u_char;
    pub fn pcap_next_ex(arg1: *mut pcap_t, arg2: *mut *mut Struct_pcap_pkthdr,
                        arg3: *mut *u_char) -> c_int;
    pub fn pcap_breakloop(arg1: *mut pcap_t);
    pub fn pcap_stats(arg1: *mut pcap_t, arg2: *mut Struct_pcap_stat) ->
     c_int;
    pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut Struct_bpf_program) ->
     c_int;
    pub fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) ->
     c_int;
    pub fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut c_schar) -> c_int;
    pub fn pcap_setnonblock(arg1: *mut pcap_t, arg2: c_int,
                            arg3: *mut c_schar) -> c_int;
    pub fn pcap_inject(arg1: *mut pcap_t, arg2: *c_void, arg3: size_t) ->
     c_int;
    pub fn pcap_sendpacket(arg1: *mut pcap_t, arg2: *u_char, arg3: c_int) ->
     c_int;
    pub fn pcap_statustostr(arg1: c_int) -> *c_schar;
    pub fn pcap_strerror(arg1: c_int) -> *c_schar;
    pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut c_schar;
    pub fn pcap_perror(arg1: *mut pcap_t, arg2: *mut c_schar);
    pub fn pcap_compile(arg1: *mut pcap_t, arg2: *mut Struct_bpf_program,
                        arg3: *c_schar, arg4: c_int, arg5: bpf_u_int32) ->
     c_int;
    pub fn pcap_compile_nopcap(arg1: c_int, arg2: c_int,
                               arg3: *mut Struct_bpf_program, arg4: *c_schar,
                               arg5: c_int, arg6: bpf_u_int32) -> c_int;
    pub fn pcap_freecode(arg1: *mut Struct_bpf_program);
    pub fn pcap_offline_filter(arg1: *Struct_bpf_program,
                               arg2: *Struct_pcap_pkthdr, arg3: *u_char) ->
     c_int;
    pub fn pcap_datalink(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut c_int) ->
     c_int;
    pub fn pcap_set_datalink(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_free_datalinks(arg1: *mut c_int);
    pub fn pcap_datalink_name_to_val(arg1: *c_schar) -> c_int;
    pub fn pcap_datalink_val_to_name(arg1: c_int) -> *c_schar;
    pub fn pcap_datalink_val_to_description(arg1: c_int) -> *c_schar;
    pub fn pcap_snapshot(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_is_swapped(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_major_version(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_minor_version(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;
    pub fn pcap_fileno(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_dump_open(arg1: *mut pcap_t, arg2: *c_schar) ->
     *mut pcap_dumper_t;
    pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) ->
     *mut pcap_dumper_t;
    pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
    pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> c_long;
    pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> c_int;
    pub fn pcap_dump_close(arg1: *mut pcap_dumper_t);
    pub fn pcap_dump(arg1: *mut u_char, arg2: *Struct_pcap_pkthdr,
                     arg3: *u_char);
    pub fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut c_schar) ->
     c_int;
    pub fn pcap_freealldevs(arg1: *mut pcap_if_t);
    pub fn pcap_lib_version() -> *c_schar;
    pub fn bpf_image(arg1: *Struct_bpf_insn, arg2: c_int) -> *mut c_schar;
    pub fn bpf_dump(arg1: *Struct_bpf_program, arg2: c_int);
    pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> c_int;
}