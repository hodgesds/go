package runtime

import (
	"reflect"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	uint32Size = unsafe.Sizeof(uint32(0))
	cqeSize    = unsafe.Sizeof(CompletionEntry{})
	sqeSize    = unsafe.Sizeof(SubmitEntry{})
)

// Setup is used to setup a io_uring using the io_uring_setup syscall.
func Setup(entries uint, params *Params) (int, error) {
	fd, _, errno := syscall.Syscall(
		SetupSyscall,
		uintptr(entries),
		uintptr(unsafe.Pointer(params)),
		uintptr(0),
	)
	if errno != 0 {
		err := errno
		return 0, err
	}
	return int(fd), nil
}

// MmapRing is used to configure the submit and completion queues, it should only
// be called after the Setup function has completed successfully.
// See:
// https://github.com/axboe/liburing/blob/master/src/setup.c#L22
func MmapRing(fd int, p *Params, sq *SubmitQueue, cq *CompletionQueue) error {
	var (
		cqPtr uintptr
		sqPtr uintptr
		errno syscall.Errno
	)
	singleMmap := p.Flags&FeatSingleMmap != 0
	sq.Size = uint32(uint(p.SqOffset.Array) + (uint(p.SqEntries) * uint(uint32Size)))
	cq.Size = uint32(uint(p.CqOffset.Cqes) + (uint(p.CqEntries) * uint(cqeSize)))

	if singleMmap {
		if cq.Size > sq.Size {
			sq.Size = cq.Size
		} else {
			cq.Size = sq.Size
		}
	}

	sqPtr, _, errno = syscall.Syscall6(
		syscall.SYS_MMAP,
		uintptr(0),
		uintptr(sq.Size),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd),
		uintptr(SqRingOffset),
	)
	if errno < 0 {
		return syscall.Errno(-errno)
	}
	sq.ptr = sqPtr

	// Conversion of a uintptr back to Pointer is not valid in general,
	// except for:
	// 3) Conversion of a Pointer to a uintptr and back, with arithmetic.

	// Go vet doesn't like this so it's probably not valid.
	sq.Head = (*uint32)(unsafe.Pointer(sq.ptr + uintptr(p.SqOffset.Head)))
	sq.Tail = (*uint32)(unsafe.Pointer(sq.ptr + uintptr(p.SqOffset.Tail)))
	sq.Mask = (*uint32)(unsafe.Pointer(sq.ptr + uintptr(p.SqOffset.RingMask)))
	sq.Flags = (*uint32)(unsafe.Pointer(sq.ptr + uintptr(p.SqOffset.Flags)))
	sq.Dropped = (*uint32)(unsafe.Pointer(sq.ptr + uintptr(p.SqOffset.Dropped)))

	// Map the sqe ring.
	sqePtr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		uintptr(0),
		uintptr(uint(p.SqEntries)*uint(sqeSize)),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd),
		uintptr(SqeRingOffset),
	)
	if errno < 0 {
		return syscall.Errno(-errno)
	}

	// Making mmap'd slices is annoying.
	// BUG: don't use composite literals
	sq.Entries = *(*[]SubmitEntry)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(sqePtr),
		Len:  int(p.SqEntries),
		Cap:  int(p.SqEntries),
	}))
	// BUG: don't use composite literals
	sq.Array = *(*[]uint32)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(sqPtr + uintptr(p.SqOffset.Array))),
		Len:  int(p.SqEntries),
		Cap:  int(p.SqEntries),
	}))
	runtime.KeepAlive(sqePtr)

	if singleMmap {
		cqPtr = sqPtr
	} else {
		cqPtr, _, errno = syscall.Syscall6(
			syscall.SYS_MMAP,
			uintptr(0),
			uintptr(cq.Size),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE,
			uintptr(fd),
			uintptr(CqRingOffset),
		)
		if errno < 0 {
			return syscall.Errno(-errno)
		}
	}

	cq.Head = (*uint32)(unsafe.Pointer(uintptr(uint(cqPtr) + uint(p.CqOffset.Head))))
	cq.Tail = (*uint32)(unsafe.Pointer(uintptr(uint(cqPtr) + uint(p.CqOffset.Tail))))
	cq.Mask = (*uint32)(unsafe.Pointer(uintptr(uint(cqPtr) + uint(p.CqOffset.RingMask))))
	cq.Overflow = (*uint32)(unsafe.Pointer(uintptr(uint(cqPtr) + uint(p.CqOffset.Overflow))))
	cq.Flags = (*uint32)(unsafe.Pointer(uintptr(uint(cqPtr) + uint(p.CqOffset.Flags))))

	// BUG: don't use composite literals
	cq.Entries = *(*[]CompletionEntry)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(uint(cqPtr) + uint(p.CqOffset.Cqes)),
		Len:  int(p.CqEntries),
		Cap:  int(p.CqEntries),
	}))
	// See: https://github.com/jlauinger/go-safer
	runtime.KeepAlive(cqPtr)

	return nil
}

// UringOpcode is an opcode for the ring.
type UringOpcode uint8

const (
	// SetupSyscall defines the syscall number for io_uring_setup.
	SetupSyscall = 425
	// EnterSyscall defines the syscall number for io_uring_enter.
	EnterSyscall = 426
	// RegisterSyscall defines the syscall number for io_uring_register.
	RegisterSyscall = 427
)

const (

	// FeatSingleMmap is used to configure a single mmap'd ring.
	FeatSingleMmap = (1 << 0)
	// FeatNoDrop is used to ensure that no CQEs are dropped.
	FeatNoDrop         = (1 << 1)
	FeatSubmitStable   = (1 << 2)
	FeatRwCurPos       = (1 << 3)
	FeatCurPersonality = (1 << 4)
)

const (
	/*
	 * sqe->flags
	 */
	SqeFixedFileBit = iota
	SqeIoDrainBit
	SqeIoLinkBit
	SqeIoHardlinkBit
	SqeAsyncBit
	SqeBufferSelectBit

	// SqeFixedFile use fixed fileset
	SqeFixedFile uint8 = (1 << SqeFixedFileBit)
	// SqeIoDrain issue after inflight IO
	SqeIoDrain uint8 = (1 << SqeIoDrainBit)
	// SqeIoLink is used to link multiple SQEs.
	SqeIoLink uint8 = (1 << SqeIoLinkBit)
	// SqeIoHardlink is a hard link to multiple SQEs
	SqeIoHardlink uint8 = (1 << SqeIoHardlinkBit)
	// SqeAsync is use to specify async io.
	SqeAsync uint8 = (1 << SqeAsyncBit)
	// SqeBufferSelect is used to specify buffer select.
	SqeBufferSelect uint8 = (1 << SqeBufferSelectBit)

	/*
	 * io_uring_setup() flags
	 */

	// SetupIOPoll io_context is polled
	SetupIOPoll uint32 = (1 << 0)
	// SetupSQPoll SQ poll thread
	SetupSQPoll uint32 = (1 << 1)
	// SetupSQAFF sq_thread_cpu is valid
	SetupSQAFF uint32 = (1 << 2)
	// SetupCqSize app defines CQ size
	SetupCqSize uint32 = (1 << 3)
	// SetupClamp clamp SQ/CQ ring sizes
	SetupClamp uint32 = (1 << 4)
	// SetupAttachWq  attach to existing wq
	SetupAttachWq uint32 = (1 << 5)
)

const (
	UringNop UringOpcode = iota
	UringReadv
	UringWritev
	UringFsync
	UringReadFixed
	UringWriteFixed
	UringPollAdd
	UringPollRemove
	UringSyncFileRange
	UringSendMsg
	UringRecvMsg
	UringTimeout
	UringTimeoutRemove
	UringAccept
	UringAsyncCancel
	UringLinkTimeout
	UringConnect
	UringFallocate
	UringOpenAt
	UringClose
	UringFilesUpdate
	UringStatx
	UringRead
	UringWrite
	UringFadvise
	UringMadvise
	UringSend
	UringRecv
	UringOpenat2
	UringEpollCtl
	UringSplice
	UringProvideBuffers
	UringRemoveBuffers
	UringOpSupported = (1 << 0)
)
const (
	/*
	 * sqe->fsync_flags
	 */

	// FsyncDatasync ...
	FsyncDatasync uint = (1 << 0)

	/*
	 * Magic offsets for the application to mmap the data it needs
	 */

	// SqRingOffset is the offset of the submission queue.
	SqRingOffset uint64 = 0
	// CqRingOffset is the offset of the completion queue.
	CqRingOffset uint64 = 0x8000000
	// SqeRingOffset is the offset of the submission queue entries.
	SqeRingOffset uint64 = 0x10000000

	/*
	 * sq_ring->flags
	 */

	// SqNeedWakeup needs io_uring_enter wakeup
	SqNeedWakeup uint32 = (1 << 0)
	SqCqOverflow uint32 = (1 << 1)

	/*
	 * io_uring_enter(2) flags
	 */

	// EnterGetEvents ...
	EnterGetEvents uint = (1 << 0)
	// EnterSqWakeup ...
	EnterSqWakeup uint = (1 << 1)

	/*
	 * io_uring_register(2) opcodes and arguments
	 */

	UringRegisterBuffers       = 0
	UringUnregisterBuffers     = 1
	UringRegisterFiles         = 2
	UringUnregisterFiles       = 3
	UringRegisterEventFd       = 4
	UringUnregisterEventfd     = 5
	UringRegisterFilesUpdate   = 6
	UringRegisterEventFdAsync  = 7
	UringRegisterProbe         = 8
	UringRegisterPersonality   = 9
	UringUnregisterPersonality = 10
)

// Params are used to configured a io uring.
type Params struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFD         uint32
	Resv         [3]uint32
	SqOffset     SQRingOffset
	CqOffset     CQRingOffset
}

// SQRingOffset describes the various submit queue offsets.
type SQRingOffset struct {
	Head     uint32
	Tail     uint32
	RingMask uint32
	Entries  uint32
	Flags    uint32
	Dropped  uint32
	Array    uint32
	Resv1    uint32
	Resv2    uint64
}

// CQRingOffset describes the various completion queue offsets.
type CQRingOffset struct {
	Head     uint32
	Tail     uint32
	RingMask uint32
	Entries  uint32
	Overflow uint32
	Cqes     uint32
	Flags    uint32
	Resv     [2]uint64
}

// SubmitEntry is an IO submission data structure (Submission Queue Entry).
type SubmitEntry struct {
	Opcode   UringOpcode /* type of operation for this sqe */
	Flags    uint8       /* IOSQE_ flags */
	Ioprio   uint16      /* ioprio for the request */
	Fd       int32       /* file descriptor to do IO on */
	Offset   uint64      /* offset into file */
	Addr     uint64      /* pointer to buffer or iovecs */
	Len      uint32      /* buffer size or number of iovecs */
	UFlags   int32
	UserData uint64
	Anon0    [24]byte /* extra padding */
}

// Reset is used to reset an SubmitEntry.
func (e *SubmitEntry) Reset() {
	e.Opcode = UringNop
	e.Flags = 0
	e.Ioprio = 0
	e.Fd = -1
	e.Offset = 0
	e.Addr = 0
	e.Len = 0
	e.UFlags = 0
	e.UserData = 0
}

// SubmitQueue represents the submit queue ring buffer.
type SubmitQueue struct {
	Size    uint32
	Head    *uint32
	Tail    *uint32
	Mask    *uint32
	Flags   *uint32
	Dropped *uint32

	// Array holds entries to be submitted; it must never be resized it is mmap'd.
	Array []uint32
	// Entries must never be resized, it is mmap'd.
	Entries []SubmitEntry
	// ptr is pointer to the start of the mmap.
	ptr uintptr

	// entered is when the ring is being entered.
	entered *uint32
	// writes is used to keep track of the number of concurrent writers to
	// the ring.
	writes *uint32
}

// Reset is used to reset all entries.
func (s *SubmitQueue) Reset() {
	for _, entry := range s.Entries {
		entry.Reset()
	}
}

// NeedWakeup is used to determine whether the submit queue needs awoken.
func (s *SubmitQueue) NeedWakeup() bool {
	return atomic.LoadUint32(s.Flags)&SqNeedWakeup != 0
}

func (s *SubmitQueue) enterLock() {
	for {
		if atomic.LoadUint32(s.writes) != 0 && atomic.LoadUint32(s.entered) == 1 {
			runtime.Gosched()
			continue
		}
		if atomic.CompareAndSwapUint32(s.entered, 0, 1) {
			break
		}
	}
}

func (s *SubmitQueue) enterUnlock() {
	atomic.StoreUint32(s.entered, 0)
}

// completeWrite is used to signal that an entry in the map has been fully
// written.
func (s *SubmitQueue) completeWrite() {
	for {
		writes := atomic.LoadUint32(s.writes)
		if writes == 0 {
			panic("invalid number of sq write completions")
		}
		if atomic.CompareAndSwapUint32(s.writes, writes, writes-1) {
			return
		}
		runtime.Gosched()
	}
}

// CompletionEntry IO completion data structure (Completion Queue Entry).
type CompletionEntry struct {
	UserData uint64 /* sqe->data submission data passed back */
	Res      int32  /* result code for this event */
	Flags    uint32
}

// IsZero returns if the CQE is zero valued.
func (c *CompletionEntry) IsZero() bool {
	return c.UserData == 0 && c.Res == 0 && c.Flags == 0
}

// CompletionQueue represents the completion queue ring buffer.
type CompletionQueue struct {
	Size     uint32
	Head     *uint32
	Tail     *uint32
	Mask     *uint32
	Overflow *uint32
	Flags    *uint32

	// Entries must never be resized, it is mmap'd.
	Entries []CompletionEntry
	ptr     uintptr
}

// Advance is used to advance the completion queue by a count.
func (c *CompletionQueue) Advance(count int) {
	atomic.AddUint32(c.Head, uint32(count))
}
