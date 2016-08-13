#define INJECTION_START(x) \
    .global x; x:

#define INJECTION_END(x) \
    INJECTION_START(x##_end)


.arm
INJECTION_START(inj_trap_arm)
0:
    wfi
    b 0b
INJECTION_END(inj_trap_arm)

.thumb
INJECTION_START(inj_trap_thumb)
1:
    wfi
    b 1b
INJECTION_END(inj_trap_thumb)
