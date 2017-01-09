#define INJECTION_START(x) \
    .global x; x:

#define INJECTION_END(x) \
    INJECTION_START(x##_end)


INJECTION_START(inj_trap_aarch64)
0:
    b 0b
INJECTION_END(inj_trap_aarch64)

INJECTION_START(inj_trap_aarch32)
// wfi
.byte 0x03
.byte 0xf0
.byte 0x20
.byte 0xe3

// b inj_trap_aarch32
.byte 0xfd
.byte 0xff
.byte 0xff
.byte 0xea
INJECTION_END(inj_trap_aarch32)

INJECTION_START(inj_trap_aarch32_thumb)
// wfi
.byte 0x30
.byte 0xbf

// b.n inj_trap_aarch32_thumb
.byte 0xfd
.byte 0xe7
INJECTION_END(inj_trap_aarch32_thumb)
