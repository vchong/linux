
@ ====================================================================
@ Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
@ project. The module is, however, dual licensed under OpenSSL and
@ CRYPTOGAMS licenses depending on where you obtain it. For further
@ details see http://www.openssl.org/~appro/cryptogams/.
@
@ Permission to use under GPL terms is granted.
@ ====================================================================

@ SHA256 block procedure for ARMv4. May 2007.

@ Performance is ~2x better than gcc 3.4 generated code and in "abso-
@ lute" terms is ~2250 cycles per 64-byte block or ~35 cycles per
@ byte [on single-issue Xscale PXA250 core].

@ July 2010.
@
@ Rescheduling for dual-issue pipeline resulted in 22% improvement on
@ Cortex A8 core and ~20 cycles per processed byte.

@ February 2011.
@
@ Profiler-assisted and platform-specific optimization resulted in 16%
@ improvement on Cortex A8 core and ~15.4 cycles per processed byte.

@ September 2013.
@
@ Add NEON implementation. On Cortex A8 it was measured to process one
@ byte in 12.5 cycles or 23% faster than integer-only code. Snapdragon
@ S4 does it in 12.5 cycles too, but it's 50% faster than integer-only
@ code (meaning that latter performs sub-optimally, nothing was done
@ about it).

@ May 2014.
@
@ Add ARMv8 code path performing at 2.0 cpb on Apple A7.

#if 0
	@ head
#endif
#ifndef __KERNEL__
# include "arm_arch.h"
#else
# define __ARM_ARCH__ __LINUX_ARM_ARCH__
# define __ARM_MAX_ARCH__ 7
#endif

.text
#if __ARM_ARCH__<7
.code	32
#else
.syntax unified
# ifdef __thumb2__
#  define adrl adr
.thumb
# else
.code   32
# endif
#endif

.type	K256,%object
.align	5
K256:
.word	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
.word	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
.word	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
.word	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
.word	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
.word	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
.word	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
.word	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
.word	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
.word	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
.word	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
.word	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
.word	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
.word	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
.word	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
.word	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
.size	K256,.-K256
.word	0				@ terminator
#if __ARM_MAX_ARCH__>=7 && !defined(__KERNEL__)
.LOPENSSL_armcap:
.word	OPENSSL_armcap_P-sha256_block_data_order
#endif
.align	5

.global	sha256_block_data_order
.type	sha256_block_data_order,%function
sha256_block_data_order:
#if __ARM_ARCH__<7
	sub	r3,pc,#8		@ sha256_block_data_order
#else
	adr	r3,sha256_block_data_order
#endif
#if __ARM_MAX_ARCH__>=7 && !defined(__KERNEL__)
	ldr	r12,.LOPENSSL_armcap
	ldr	r12,[r3,r12]		@ OPENSSL_armcap_P
	tst	r12,#ARMV8_SHA256
	bne	.LARMv8
	tst	r12,#ARMV7_NEON
	bne	.LNEON
#endif
	add	x2,x1,x2,lsl#6	@ len to point at the end of inp
	stmdb	sp!,{x0,x1,x2,r4-r11,lr}
	ldmia	x0,{x4,x5,x6,x7,x8,x9,x10,x11}
	sub	x14,r3,#256+32	@ K256
	sub	sp,sp,#16*4		@ alloca(X[16])
.Loop:
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x5,x6		@ magic
	eor	x12,x12,x12
#if 0
bf Lrounds_16_xx - call BODY_00_15 0
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 0
# if 0==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x8,x8,ror#5
	add	x4,x4,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x8,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 0
	add	x4,x4,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 0==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x8,x8,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x8,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x11,x11,x2			@ h+=X[i]
	str	x2,[sp,#0*4]
	eor	x2,x9,x10
	add	x11,x11,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x8
	add	x11,x11,x12			@ h+=K256[i]
	eor	x2,x2,x10			@ Ch(e,f,g)
	eor	x0,x4,x4,ror#11
	add	x11,x11,x2			@ h+=Ch(e,f,g)
#if 0==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 0<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x4,x5			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#2*4]		@ from future BODY_16_xx
	eor	x12,x4,x5			@ a^b, b^c in next round
	ldr	x1,[sp,#15*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x4,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x7,x7,x11			@ d+=h
	eor	x3,x3,x5			@ Maj(a,b,c)
	add	x11,x11,x0,ror#2	@ h+=Sigma0(a)
	@ add	x11,x11,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 1
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 1
# if 1==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x7,x7,ror#5
	add	x11,x11,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x7,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 1
	add	x11,x11,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 1==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x7,x7,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x7,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x10,x10,x2			@ h+=X[i]
	str	x2,[sp,#1*4]
	eor	x2,x8,x9
	add	x10,x10,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x7
	add	x10,x10,x3			@ h+=K256[i]
	eor	x2,x2,x9			@ Ch(e,f,g)
	eor	x0,x11,x11,ror#11
	add	x10,x10,x2			@ h+=Ch(e,f,g)
#if 1==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 1<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x11,x4			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#3*4]		@ from future BODY_16_xx
	eor	x3,x11,x4			@ a^b, b^c in next round
	ldr	x1,[sp,#0*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x11,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x6,x6,x10			@ d+=h
	eor	x12,x12,x4			@ Maj(a,b,c)
	add	x10,x10,x0,ror#2	@ h+=Sigma0(a)
	@ add	x10,x10,x12			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 2
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 2
# if 2==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x6,x6,ror#5
	add	x10,x10,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x6,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 2
	add	x10,x10,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 2==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x6,x6,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x6,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x9,x9,x2			@ h+=X[i]
	str	x2,[sp,#2*4]
	eor	x2,x7,x8
	add	x9,x9,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x6
	add	x9,x9,x12			@ h+=K256[i]
	eor	x2,x2,x8			@ Ch(e,f,g)
	eor	x0,x10,x10,ror#11
	add	x9,x9,x2			@ h+=Ch(e,f,g)
#if 2==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 2<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x10,x11			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#4*4]		@ from future BODY_16_xx
	eor	x12,x10,x11			@ a^b, b^c in next round
	ldr	x1,[sp,#1*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x10,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x5,x5,x9			@ d+=h
	eor	x3,x3,x11			@ Maj(a,b,c)
	add	x9,x9,x0,ror#2	@ h+=Sigma0(a)
	@ add	x9,x9,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 3
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 3
# if 3==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x5,x5,ror#5
	add	x9,x9,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x5,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 3
	add	x9,x9,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 3==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x5,x5,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x5,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x8,x8,x2			@ h+=X[i]
	str	x2,[sp,#3*4]
	eor	x2,x6,x7
	add	x8,x8,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x5
	add	x8,x8,x3			@ h+=K256[i]
	eor	x2,x2,x7			@ Ch(e,f,g)
	eor	x0,x9,x9,ror#11
	add	x8,x8,x2			@ h+=Ch(e,f,g)
#if 3==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 3<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x9,x10			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#5*4]		@ from future BODY_16_xx
	eor	x3,x9,x10			@ a^b, b^c in next round
	ldr	x1,[sp,#2*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x9,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x4,x4,x8			@ d+=h
	eor	x12,x12,x10			@ Maj(a,b,c)
	add	x8,x8,x0,ror#2	@ h+=Sigma0(a)
	@ add	x8,x8,x12			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 4
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 4
# if 4==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x4,x4,ror#5
	add	x8,x8,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x4,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 4
	add	x8,x8,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 4==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x4,x4,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x4,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x7,x7,x2			@ h+=X[i]
	str	x2,[sp,#4*4]
	eor	x2,x5,x6
	add	x7,x7,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x4
	add	x7,x7,x12			@ h+=K256[i]
	eor	x2,x2,x6			@ Ch(e,f,g)
	eor	x0,x8,x8,ror#11
	add	x7,x7,x2			@ h+=Ch(e,f,g)
#if 4==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 4<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x8,x9			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#6*4]		@ from future BODY_16_xx
	eor	x12,x8,x9			@ a^b, b^c in next round
	ldr	x1,[sp,#3*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x8,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x11,x11,x7			@ d+=h
	eor	x3,x3,x9			@ Maj(a,b,c)
	add	x7,x7,x0,ror#2	@ h+=Sigma0(a)
	@ add	x7,x7,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 5
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 5
# if 5==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x11,x11,ror#5
	add	x7,x7,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x11,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 5
	add	x7,x7,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 5==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x11,x11,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x11,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x6,x6,x2			@ h+=X[i]
	str	x2,[sp,#5*4]
	eor	x2,x4,x5
	add	x6,x6,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x11
	add	x6,x6,x3			@ h+=K256[i]
	eor	x2,x2,x5			@ Ch(e,f,g)
	eor	x0,x7,x7,ror#11
	add	x6,x6,x2			@ h+=Ch(e,f,g)
#if 5==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 5<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x7,x8			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#7*4]		@ from future BODY_16_xx
	eor	x3,x7,x8			@ a^b, b^c in next round
	ldr	x1,[sp,#4*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x7,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x10,x10,x6			@ d+=h
	eor	x12,x12,x8			@ Maj(a,b,c)
	add	x6,x6,x0,ror#2	@ h+=Sigma0(a)
	@ add	x6,x6,x12			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 6
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 6
# if 6==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x10,x10,ror#5
	add	x6,x6,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x10,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 6
	add	x6,x6,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 6==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x10,x10,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x10,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x5,x5,x2			@ h+=X[i]
	str	x2,[sp,#6*4]
	eor	x2,x11,x4
	add	x5,x5,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x10
	add	x5,x5,x12			@ h+=K256[i]
	eor	x2,x2,x4			@ Ch(e,f,g)
	eor	x0,x6,x6,ror#11
	add	x5,x5,x2			@ h+=Ch(e,f,g)
#if 6==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 6<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x6,x7			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#8*4]		@ from future BODY_16_xx
	eor	x12,x6,x7			@ a^b, b^c in next round
	ldr	x1,[sp,#5*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x6,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x9,x9,x5			@ d+=h
	eor	x3,x3,x7			@ Maj(a,b,c)
	add	x5,x5,x0,ror#2	@ h+=Sigma0(a)
	@ add	x5,x5,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 7
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 7
# if 7==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x9,x9,ror#5
	add	x5,x5,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x9,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 7
	add	x5,x5,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 7==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x9,x9,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x9,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x4,x4,x2			@ h+=X[i]
	str	x2,[sp,#7*4]
	eor	x2,x10,x11
	add	x4,x4,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x9
	add	x4,x4,x3			@ h+=K256[i]
	eor	x2,x2,x11			@ Ch(e,f,g)
	eor	x0,x5,x5,ror#11
	add	x4,x4,x2			@ h+=Ch(e,f,g)
#if 7==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 7<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x5,x6			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#9*4]		@ from future BODY_16_xx
	eor	x3,x5,x6			@ a^b, b^c in next round
	ldr	x1,[sp,#6*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x5,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x8,x8,x4			@ d+=h
	eor	x12,x12,x6			@ Maj(a,b,c)
	add	x4,x4,x0,ror#2	@ h+=Sigma0(a)
	@ add	x4,x4,x12			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 8
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 8
# if 8==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x8,x8,ror#5
	add	x4,x4,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x8,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 8
	add	x4,x4,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 8==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x8,x8,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x8,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x11,x11,x2			@ h+=X[i]
	str	x2,[sp,#8*4]
	eor	x2,x9,x10
	add	x11,x11,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x8
	add	x11,x11,x12			@ h+=K256[i]
	eor	x2,x2,x10			@ Ch(e,f,g)
	eor	x0,x4,x4,ror#11
	add	x11,x11,x2			@ h+=Ch(e,f,g)
#if 8==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 8<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x4,x5			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#10*4]		@ from future BODY_16_xx
	eor	x12,x4,x5			@ a^b, b^c in next round
	ldr	x1,[sp,#7*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x4,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x7,x7,x11			@ d+=h
	eor	x3,x3,x5			@ Maj(a,b,c)
	add	x11,x11,x0,ror#2	@ h+=Sigma0(a)
	@ add	x11,x11,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 9
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 9
# if 9==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x7,x7,ror#5
	add	x11,x11,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x7,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 9
	add	x11,x11,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 9==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x7,x7,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x7,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x10,x10,x2			@ h+=X[i]
	str	x2,[sp,#9*4]
	eor	x2,x8,x9
	add	x10,x10,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x7
	add	x10,x10,x3			@ h+=K256[i]
	eor	x2,x2,x9			@ Ch(e,f,g)
	eor	x0,x11,x11,ror#11
	add	x10,x10,x2			@ h+=Ch(e,f,g)
#if 9==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 9<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x11,x4			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#11*4]		@ from future BODY_16_xx
	eor	x3,x11,x4			@ a^b, b^c in next round
	ldr	x1,[sp,#8*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x11,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x6,x6,x10			@ d+=h
	eor	x12,x12,x4			@ Maj(a,b,c)
	add	x10,x10,x0,ror#2	@ h+=Sigma0(a)
	@ add	x10,x10,x12			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 10
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 10
# if 10==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x6,x6,ror#5
	add	x10,x10,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x6,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 10
	add	x10,x10,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 10==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x6,x6,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x6,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x9,x9,x2			@ h+=X[i]
	str	x2,[sp,#10*4]
	eor	x2,x7,x8
	add	x9,x9,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x6
	add	x9,x9,x12			@ h+=K256[i]
	eor	x2,x2,x8			@ Ch(e,f,g)
	eor	x0,x10,x10,ror#11
	add	x9,x9,x2			@ h+=Ch(e,f,g)
#if 10==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 10<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x10,x11			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#12*4]		@ from future BODY_16_xx
	eor	x12,x10,x11			@ a^b, b^c in next round
	ldr	x1,[sp,#9*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x10,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x5,x5,x9			@ d+=h
	eor	x3,x3,x11			@ Maj(a,b,c)
	add	x9,x9,x0,ror#2	@ h+=Sigma0(a)
	@ add	x9,x9,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 11
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 11
# if 11==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x5,x5,ror#5
	add	x9,x9,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x5,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 11
	add	x9,x9,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 11==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x5,x5,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x5,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x8,x8,x2			@ h+=X[i]
	str	x2,[sp,#11*4]
	eor	x2,x6,x7
	add	x8,x8,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x5
	add	x8,x8,x3			@ h+=K256[i]
	eor	x2,x2,x7			@ Ch(e,f,g)
	eor	x0,x9,x9,ror#11
	add	x8,x8,x2			@ h+=Ch(e,f,g)
#if 11==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 11<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x9,x10			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#13*4]		@ from future BODY_16_xx
	eor	x3,x9,x10			@ a^b, b^c in next round
	ldr	x1,[sp,#10*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x9,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x4,x4,x8			@ d+=h
	eor	x12,x12,x10			@ Maj(a,b,c)
	add	x8,x8,x0,ror#2	@ h+=Sigma0(a)
	@ add	x8,x8,x12			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 12
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 12
# if 12==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x4,x4,ror#5
	add	x8,x8,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x4,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 12
	add	x8,x8,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 12==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x4,x4,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x4,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x7,x7,x2			@ h+=X[i]
	str	x2,[sp,#12*4]
	eor	x2,x5,x6
	add	x7,x7,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x4
	add	x7,x7,x12			@ h+=K256[i]
	eor	x2,x2,x6			@ Ch(e,f,g)
	eor	x0,x8,x8,ror#11
	add	x7,x7,x2			@ h+=Ch(e,f,g)
#if 12==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 12<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x8,x9			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#14*4]		@ from future BODY_16_xx
	eor	x12,x8,x9			@ a^b, b^c in next round
	ldr	x1,[sp,#11*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x8,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x11,x11,x7			@ d+=h
	eor	x3,x3,x9			@ Maj(a,b,c)
	add	x7,x7,x0,ror#2	@ h+=Sigma0(a)
	@ add	x7,x7,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 13
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 13
# if 13==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x11,x11,ror#5
	add	x7,x7,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x11,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 13
	add	x7,x7,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 13==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x11,x11,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x11,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x6,x6,x2			@ h+=X[i]
	str	x2,[sp,#13*4]
	eor	x2,x4,x5
	add	x6,x6,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x11
	add	x6,x6,x3			@ h+=K256[i]
	eor	x2,x2,x5			@ Ch(e,f,g)
	eor	x0,x7,x7,ror#11
	add	x6,x6,x2			@ h+=Ch(e,f,g)
#if 13==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 13<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x7,x8			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#15*4]		@ from future BODY_16_xx
	eor	x3,x7,x8			@ a^b, b^c in next round
	ldr	x1,[sp,#12*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x7,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x10,x10,x6			@ d+=h
	eor	x12,x12,x8			@ Maj(a,b,c)
	add	x6,x6,x0,ror#2	@ h+=Sigma0(a)
	@ add	x6,x6,x12			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 14
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 14
# if 14==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x10,x10,ror#5
	add	x6,x6,x12			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x10,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 14
	add	x6,x6,x12			@ h+=Maj(a,b,c) from the past
	ldrb	x12,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x12,lsl#8
	ldrb	x12,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 14==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x10,x10,ror#5
	orr	x2,x2,x12,lsl#24
	eor	x0,x0,x10,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x5,x5,x2			@ h+=X[i]
	str	x2,[sp,#14*4]
	eor	x2,x11,x4
	add	x5,x5,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x10
	add	x5,x5,x12			@ h+=K256[i]
	eor	x2,x2,x4			@ Ch(e,f,g)
	eor	x0,x6,x6,ror#11
	add	x5,x5,x2			@ h+=Ch(e,f,g)
#if 14==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 14<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x6,x7			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#0*4]		@ from future BODY_16_xx
	eor	x12,x6,x7			@ a^b, b^c in next round
	ldr	x1,[sp,#13*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x6,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x9,x9,x5			@ d+=h
	eor	x3,x3,x7			@ Maj(a,b,c)
	add	x5,x5,x0,ror#2	@ h+=Sigma0(a)
	@ add	x5,x5,x3			@ h+=Maj(a,b,c)
#if 0
bf Lrounds_16_xx - call BODY_00_15 15
#endif
#if __ARM_ARCH__>=7
	@ ldr	x2,[x1],#4			@ 15
# if 15==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x9,x9,ror#5
	add	x5,x5,x3			@ h+=Maj(a,b,c) from the past
	eor	x0,x0,x9,ror#19	@ Sigma1(e)
# ifndef __ARMEB__
	rev	x2,x2
# endif
#else
	@ ldrb	x2,[x1,#3]			@ 15
	add	x5,x5,x3			@ h+=Maj(a,b,c) from the past
	ldrb	x3,[x1,#2]
	ldrb	x0,[x1,#1]
	orr	x2,x2,x3,lsl#8
	ldrb	x3,[x1],#4
	orr	x2,x2,x0,lsl#16
# if 15==15
	str	x1,[sp,#17*4]			@ make room for x1
# endif
	eor	x0,x9,x9,ror#5
	orr	x2,x2,x3,lsl#24
	eor	x0,x0,x9,ror#19	@ Sigma1(e)
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x4,x4,x2			@ h+=X[i]
	str	x2,[sp,#15*4]
	eor	x2,x10,x11
	add	x4,x4,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x9
	add	x4,x4,x3			@ h+=K256[i]
	eor	x2,x2,x11			@ Ch(e,f,g)
	eor	x0,x5,x5,ror#11
	add	x4,x4,x2			@ h+=Ch(e,f,g)
#if 15==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 15<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x5,x6			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#1*4]		@ from future BODY_16_xx
	eor	x3,x5,x6			@ a^b, b^c in next round
	ldr	x1,[sp,#14*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x5,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x8,x8,x4			@ d+=h
	eor	x12,x12,x6			@ Maj(a,b,c)
	add	x4,x4,x0,ror#2	@ h+=Sigma0(a)
	@ add	x4,x4,x12			@ h+=Maj(a,b,c)
.Lrounds_16_xx:
#if 0
Lrounds_16_xx call BODY_16_XX 16
#endif
	@ ldr	x2,[sp,#1*4]		@ 16
	@ ldr	x1,[sp,#14*4]
	mov	x0,x2,ror#7
	add	x4,x4,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#0*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#9*4]

	add	x12,x12,x0
	eor	x0,x8,x8,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x8,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=16
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x11,x11,x2			@ h+=X[i]
	str	x2,[sp,#0*4]
	eor	x2,x9,x10
	add	x11,x11,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x8
	add	x11,x11,x12			@ h+=K256[i]
	eor	x2,x2,x10			@ Ch(e,f,g)
	eor	x0,x4,x4,ror#11
	add	x11,x11,x2			@ h+=Ch(e,f,g)
#if 16==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 16<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x4,x5			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#2*4]		@ from future BODY_16_xx
	eor	x12,x4,x5			@ a^b, b^c in next round
	ldr	x1,[sp,#15*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x4,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x7,x7,x11			@ d+=h
	eor	x3,x3,x5			@ Maj(a,b,c)
	add	x11,x11,x0,ror#2	@ h+=Sigma0(a)
	@ add	x11,x11,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 17
#endif
	@ ldr	x2,[sp,#2*4]		@ 17
	@ ldr	x1,[sp,#15*4]
	mov	x0,x2,ror#7
	add	x11,x11,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#1*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#10*4]

	add	x3,x3,x0
	eor	x0,x7,x7,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x7,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=17
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x10,x10,x2			@ h+=X[i]
	str	x2,[sp,#1*4]
	eor	x2,x8,x9
	add	x10,x10,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x7
	add	x10,x10,x3			@ h+=K256[i]
	eor	x2,x2,x9			@ Ch(e,f,g)
	eor	x0,x11,x11,ror#11
	add	x10,x10,x2			@ h+=Ch(e,f,g)
#if 17==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 17<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x11,x4			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#3*4]		@ from future BODY_16_xx
	eor	x3,x11,x4			@ a^b, b^c in next round
	ldr	x1,[sp,#0*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x11,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x6,x6,x10			@ d+=h
	eor	x12,x12,x4			@ Maj(a,b,c)
	add	x10,x10,x0,ror#2	@ h+=Sigma0(a)
	@ add	x10,x10,x12			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 18
#endif
	@ ldr	x2,[sp,#3*4]		@ 18
	@ ldr	x1,[sp,#0*4]
	mov	x0,x2,ror#7
	add	x10,x10,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#2*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#11*4]

	add	x12,x12,x0
	eor	x0,x6,x6,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x6,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=18
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x9,x9,x2			@ h+=X[i]
	str	x2,[sp,#2*4]
	eor	x2,x7,x8
	add	x9,x9,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x6
	add	x9,x9,x12			@ h+=K256[i]
	eor	x2,x2,x8			@ Ch(e,f,g)
	eor	x0,x10,x10,ror#11
	add	x9,x9,x2			@ h+=Ch(e,f,g)
#if 18==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 18<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x10,x11			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#4*4]		@ from future BODY_16_xx
	eor	x12,x10,x11			@ a^b, b^c in next round
	ldr	x1,[sp,#1*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x10,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x5,x5,x9			@ d+=h
	eor	x3,x3,x11			@ Maj(a,b,c)
	add	x9,x9,x0,ror#2	@ h+=Sigma0(a)
	@ add	x9,x9,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 19
#endif
	@ ldr	x2,[sp,#4*4]		@ 19
	@ ldr	x1,[sp,#1*4]
	mov	x0,x2,ror#7
	add	x9,x9,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#3*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#12*4]

	add	x3,x3,x0
	eor	x0,x5,x5,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x5,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=19
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x8,x8,x2			@ h+=X[i]
	str	x2,[sp,#3*4]
	eor	x2,x6,x7
	add	x8,x8,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x5
	add	x8,x8,x3			@ h+=K256[i]
	eor	x2,x2,x7			@ Ch(e,f,g)
	eor	x0,x9,x9,ror#11
	add	x8,x8,x2			@ h+=Ch(e,f,g)
#if 19==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 19<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x9,x10			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#5*4]		@ from future BODY_16_xx
	eor	x3,x9,x10			@ a^b, b^c in next round
	ldr	x1,[sp,#2*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x9,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x4,x4,x8			@ d+=h
	eor	x12,x12,x10			@ Maj(a,b,c)
	add	x8,x8,x0,ror#2	@ h+=Sigma0(a)
	@ add	x8,x8,x12			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 20
#endif
	@ ldr	x2,[sp,#5*4]		@ 20
	@ ldr	x1,[sp,#2*4]
	mov	x0,x2,ror#7
	add	x8,x8,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#4*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#13*4]

	add	x12,x12,x0
	eor	x0,x4,x4,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x4,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=20
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x7,x7,x2			@ h+=X[i]
	str	x2,[sp,#4*4]
	eor	x2,x5,x6
	add	x7,x7,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x4
	add	x7,x7,x12			@ h+=K256[i]
	eor	x2,x2,x6			@ Ch(e,f,g)
	eor	x0,x8,x8,ror#11
	add	x7,x7,x2			@ h+=Ch(e,f,g)
#if 20==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 20<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x8,x9			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#6*4]		@ from future BODY_16_xx
	eor	x12,x8,x9			@ a^b, b^c in next round
	ldr	x1,[sp,#3*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x8,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x11,x11,x7			@ d+=h
	eor	x3,x3,x9			@ Maj(a,b,c)
	add	x7,x7,x0,ror#2	@ h+=Sigma0(a)
	@ add	x7,x7,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 21
#endif
	@ ldr	x2,[sp,#6*4]		@ 21
	@ ldr	x1,[sp,#3*4]
	mov	x0,x2,ror#7
	add	x7,x7,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#5*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#14*4]

	add	x3,x3,x0
	eor	x0,x11,x11,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x11,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=21
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x6,x6,x2			@ h+=X[i]
	str	x2,[sp,#5*4]
	eor	x2,x4,x5
	add	x6,x6,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x11
	add	x6,x6,x3			@ h+=K256[i]
	eor	x2,x2,x5			@ Ch(e,f,g)
	eor	x0,x7,x7,ror#11
	add	x6,x6,x2			@ h+=Ch(e,f,g)
#if 21==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 21<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x7,x8			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#7*4]		@ from future BODY_16_xx
	eor	x3,x7,x8			@ a^b, b^c in next round
	ldr	x1,[sp,#4*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x7,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x10,x10,x6			@ d+=h
	eor	x12,x12,x8			@ Maj(a,b,c)
	add	x6,x6,x0,ror#2	@ h+=Sigma0(a)
	@ add	x6,x6,x12			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 22
#endif
	@ ldr	x2,[sp,#7*4]		@ 22
	@ ldr	x1,[sp,#4*4]
	mov	x0,x2,ror#7
	add	x6,x6,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#6*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#15*4]

	add	x12,x12,x0
	eor	x0,x10,x10,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x10,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=22
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x5,x5,x2			@ h+=X[i]
	str	x2,[sp,#6*4]
	eor	x2,x11,x4
	add	x5,x5,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x10
	add	x5,x5,x12			@ h+=K256[i]
	eor	x2,x2,x4			@ Ch(e,f,g)
	eor	x0,x6,x6,ror#11
	add	x5,x5,x2			@ h+=Ch(e,f,g)
#if 22==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 22<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x6,x7			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#8*4]		@ from future BODY_16_xx
	eor	x12,x6,x7			@ a^b, b^c in next round
	ldr	x1,[sp,#5*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x6,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x9,x9,x5			@ d+=h
	eor	x3,x3,x7			@ Maj(a,b,c)
	add	x5,x5,x0,ror#2	@ h+=Sigma0(a)
	@ add	x5,x5,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 23
#endif
	@ ldr	x2,[sp,#8*4]		@ 23
	@ ldr	x1,[sp,#5*4]
	mov	x0,x2,ror#7
	add	x5,x5,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#7*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#0*4]

	add	x3,x3,x0
	eor	x0,x9,x9,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x9,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=23
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x4,x4,x2			@ h+=X[i]
	str	x2,[sp,#7*4]
	eor	x2,x10,x11
	add	x4,x4,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x9
	add	x4,x4,x3			@ h+=K256[i]
	eor	x2,x2,x11			@ Ch(e,f,g)
	eor	x0,x5,x5,ror#11
	add	x4,x4,x2			@ h+=Ch(e,f,g)
#if 23==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 23<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x5,x6			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#9*4]		@ from future BODY_16_xx
	eor	x3,x5,x6			@ a^b, b^c in next round
	ldr	x1,[sp,#6*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x5,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x8,x8,x4			@ d+=h
	eor	x12,x12,x6			@ Maj(a,b,c)
	add	x4,x4,x0,ror#2	@ h+=Sigma0(a)
	@ add	x4,x4,x12			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 24
#endif
	@ ldr	x2,[sp,#9*4]		@ 24
	@ ldr	x1,[sp,#6*4]
	mov	x0,x2,ror#7
	add	x4,x4,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#8*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#1*4]

	add	x12,x12,x0
	eor	x0,x8,x8,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x8,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=24
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x11,x11,x2			@ h+=X[i]
	str	x2,[sp,#8*4]
	eor	x2,x9,x10
	add	x11,x11,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x8
	add	x11,x11,x12			@ h+=K256[i]
	eor	x2,x2,x10			@ Ch(e,f,g)
	eor	x0,x4,x4,ror#11
	add	x11,x11,x2			@ h+=Ch(e,f,g)
#if 24==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 24<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x4,x5			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#10*4]		@ from future BODY_16_xx
	eor	x12,x4,x5			@ a^b, b^c in next round
	ldr	x1,[sp,#7*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x4,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x7,x7,x11			@ d+=h
	eor	x3,x3,x5			@ Maj(a,b,c)
	add	x11,x11,x0,ror#2	@ h+=Sigma0(a)
	@ add	x11,x11,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 25
#endif
	@ ldr	x2,[sp,#10*4]		@ 25
	@ ldr	x1,[sp,#7*4]
	mov	x0,x2,ror#7
	add	x11,x11,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#9*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#2*4]

	add	x3,x3,x0
	eor	x0,x7,x7,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x7,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=25
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x10,x10,x2			@ h+=X[i]
	str	x2,[sp,#9*4]
	eor	x2,x8,x9
	add	x10,x10,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x7
	add	x10,x10,x3			@ h+=K256[i]
	eor	x2,x2,x9			@ Ch(e,f,g)
	eor	x0,x11,x11,ror#11
	add	x10,x10,x2			@ h+=Ch(e,f,g)
#if 25==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 25<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x11,x4			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#11*4]		@ from future BODY_16_xx
	eor	x3,x11,x4			@ a^b, b^c in next round
	ldr	x1,[sp,#8*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x11,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x6,x6,x10			@ d+=h
	eor	x12,x12,x4			@ Maj(a,b,c)
	add	x10,x10,x0,ror#2	@ h+=Sigma0(a)
	@ add	x10,x10,x12			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 26
#endif
	@ ldr	x2,[sp,#11*4]		@ 26
	@ ldr	x1,[sp,#8*4]
	mov	x0,x2,ror#7
	add	x10,x10,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#10*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#3*4]

	add	x12,x12,x0
	eor	x0,x6,x6,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x6,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=26
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x9,x9,x2			@ h+=X[i]
	str	x2,[sp,#10*4]
	eor	x2,x7,x8
	add	x9,x9,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x6
	add	x9,x9,x12			@ h+=K256[i]
	eor	x2,x2,x8			@ Ch(e,f,g)
	eor	x0,x10,x10,ror#11
	add	x9,x9,x2			@ h+=Ch(e,f,g)
#if 26==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 26<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x10,x11			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#12*4]		@ from future BODY_16_xx
	eor	x12,x10,x11			@ a^b, b^c in next round
	ldr	x1,[sp,#9*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x10,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x5,x5,x9			@ d+=h
	eor	x3,x3,x11			@ Maj(a,b,c)
	add	x9,x9,x0,ror#2	@ h+=Sigma0(a)
	@ add	x9,x9,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 27
#endif
	@ ldr	x2,[sp,#12*4]		@ 27
	@ ldr	x1,[sp,#9*4]
	mov	x0,x2,ror#7
	add	x9,x9,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#11*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#4*4]

	add	x3,x3,x0
	eor	x0,x5,x5,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x5,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=27
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x8,x8,x2			@ h+=X[i]
	str	x2,[sp,#11*4]
	eor	x2,x6,x7
	add	x8,x8,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x5
	add	x8,x8,x3			@ h+=K256[i]
	eor	x2,x2,x7			@ Ch(e,f,g)
	eor	x0,x9,x9,ror#11
	add	x8,x8,x2			@ h+=Ch(e,f,g)
#if 27==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 27<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x9,x10			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#13*4]		@ from future BODY_16_xx
	eor	x3,x9,x10			@ a^b, b^c in next round
	ldr	x1,[sp,#10*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x9,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x4,x4,x8			@ d+=h
	eor	x12,x12,x10			@ Maj(a,b,c)
	add	x8,x8,x0,ror#2	@ h+=Sigma0(a)
	@ add	x8,x8,x12			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 28
#endif
	@ ldr	x2,[sp,#13*4]		@ 28
	@ ldr	x1,[sp,#10*4]
	mov	x0,x2,ror#7
	add	x8,x8,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#12*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#5*4]

	add	x12,x12,x0
	eor	x0,x4,x4,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x4,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=28
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x7,x7,x2			@ h+=X[i]
	str	x2,[sp,#12*4]
	eor	x2,x5,x6
	add	x7,x7,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x4
	add	x7,x7,x12			@ h+=K256[i]
	eor	x2,x2,x6			@ Ch(e,f,g)
	eor	x0,x8,x8,ror#11
	add	x7,x7,x2			@ h+=Ch(e,f,g)
#if 28==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 28<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x8,x9			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#14*4]		@ from future BODY_16_xx
	eor	x12,x8,x9			@ a^b, b^c in next round
	ldr	x1,[sp,#11*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x8,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x11,x11,x7			@ d+=h
	eor	x3,x3,x9			@ Maj(a,b,c)
	add	x7,x7,x0,ror#2	@ h+=Sigma0(a)
	@ add	x7,x7,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 29
#endif
	@ ldr	x2,[sp,#14*4]		@ 29
	@ ldr	x1,[sp,#11*4]
	mov	x0,x2,ror#7
	add	x7,x7,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#13*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#6*4]

	add	x3,x3,x0
	eor	x0,x11,x11,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x11,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=29
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x6,x6,x2			@ h+=X[i]
	str	x2,[sp,#13*4]
	eor	x2,x4,x5
	add	x6,x6,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x11
	add	x6,x6,x3			@ h+=K256[i]
	eor	x2,x2,x5			@ Ch(e,f,g)
	eor	x0,x7,x7,ror#11
	add	x6,x6,x2			@ h+=Ch(e,f,g)
#if 29==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 29<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x7,x8			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#15*4]		@ from future BODY_16_xx
	eor	x3,x7,x8			@ a^b, b^c in next round
	ldr	x1,[sp,#12*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x7,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x10,x10,x6			@ d+=h
	eor	x12,x12,x8			@ Maj(a,b,c)
	add	x6,x6,x0,ror#2	@ h+=Sigma0(a)
	@ add	x6,x6,x12			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 30
#endif
	@ ldr	x2,[sp,#15*4]		@ 30
	@ ldr	x1,[sp,#12*4]
	mov	x0,x2,ror#7
	add	x6,x6,x12			@ h+=Maj(a,b,c) from the past
	mov	x12,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x12,x12,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#14*4]
	eor	x12,x12,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#7*4]

	add	x12,x12,x0
	eor	x0,x10,x10,ror#5	@ from BODY_00_15
	add	x2,x2,x12
	eor	x0,x0,x10,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=30
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x12,[x14],#4			@ *K256++
	add	x5,x5,x2			@ h+=X[i]
	str	x2,[sp,#14*4]
	eor	x2,x11,x4
	add	x5,x5,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x10
	add	x5,x5,x12			@ h+=K256[i]
	eor	x2,x2,x4			@ Ch(e,f,g)
	eor	x0,x6,x6,ror#11
	add	x5,x5,x2			@ h+=Ch(e,f,g)
#if 30==31
	and	x12,x12,#0xff
	cmp	x12,#0xf2			@ done?
#endif
#if 30<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x12,x6,x7			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#0*4]		@ from future BODY_16_xx
	eor	x12,x6,x7			@ a^b, b^c in next round
	ldr	x1,[sp,#13*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x6,ror#20	@ Sigma0(a)
	and	x3,x3,x12			@ (b^c)&=(a^b)
	add	x9,x9,x5			@ d+=h
	eor	x3,x3,x7			@ Maj(a,b,c)
	add	x5,x5,x0,ror#2	@ h+=Sigma0(a)
	@ add	x5,x5,x3			@ h+=Maj(a,b,c)
#if 0
Lrounds_16_xx call BODY_16_XX 31
#endif
	@ ldr	x2,[sp,#0*4]		@ 31
	@ ldr	x1,[sp,#13*4]
	mov	x0,x2,ror#7
	add	x5,x5,x3			@ h+=Maj(a,b,c) from the past
	mov	x3,x1,ror#17
	eor	x0,x0,x2,ror#18
	eor	x3,x3,x1,ror#19
	eor	x0,x0,x2,lsr#3	@ sigma0(X[i+1])
	ldr	x2,[sp,#15*4]
	eor	x3,x3,x1,lsr#10	@ sigma1(X[i+14])
	ldr	x1,[sp,#8*4]

	add	x3,x3,x0
	eor	x0,x9,x9,ror#5	@ from BODY_00_15
	add	x2,x2,x3
	eor	x0,x0,x9,ror#19	@ Sigma1(e)
	add	x2,x2,x1			@ X[i]
#if 0
	@ BODY_16_XX calls BODY_00_15 i=31
#endif
#if 0
	@ BODY_00_15 - 2
#endif
	ldr	x3,[x14],#4			@ *K256++
	add	x4,x4,x2			@ h+=X[i]
	str	x2,[sp,#15*4]
	eor	x2,x10,x11
	add	x4,x4,x0,ror#6	@ h+=Sigma1(e)
	and	x2,x2,x9
	add	x4,x4,x3			@ h+=K256[i]
	eor	x2,x2,x11			@ Ch(e,f,g)
	eor	x0,x5,x5,ror#11
	add	x4,x4,x2			@ h+=Ch(e,f,g)
#if 31==31
	and	x3,x3,#0xff
	cmp	x3,#0xf2			@ done?
#endif
#if 31<15
# if __ARM_ARCH__>=7
	ldr	x2,[x1],#4			@ prefetch
# else
	ldrb	x2,[x1,#3]
# endif
	eor	x3,x5,x6			@ a^b, b^c in next round
#else
	ldr	x2,[sp,#1*4]		@ from future BODY_16_xx
	eor	x3,x5,x6			@ a^b, b^c in next round
	ldr	x1,[sp,#14*4]	@ from future BODY_16_xx
#endif
	eor	x0,x0,x5,ror#20	@ Sigma0(a)
	and	x12,x12,x3			@ (b^c)&=(a^b)
	add	x8,x8,x4			@ d+=h
	eor	x12,x12,x6			@ Maj(a,b,c)
	add	x4,x4,x0,ror#2	@ h+=Sigma0(a)
	@ add	x4,x4,x12			@ h+=Maj(a,b,c)
#if 0
	@ after .Lrounds_16_xx
#endif
#if __ARM_ARCH__>=7
	ite	eq			@ Thumb2 thing, sanity check in ARM
#endif
	ldreq	x3,[sp,#16*4]		@ pull ctx
	bne	.Lrounds_16_xx

	add	x4,x4,x12		@ h+=Maj(a,b,c) from the past
	ldr	x0,[x3,#0]
	ldr	x2,[x3,#4]
	ldr	x12,[x3,#8]
	add	x4,x4,x0
	ldr	x0,[x3,#12]
	add	x5,x5,x2
	ldr	x2,[x3,#16]
	add	x6,x6,x12
	ldr	x12,[x3,#20]
	add	x7,x7,x0
	ldr	x0,[x3,#24]
	add	x8,x8,x2
	ldr	x2,[x3,#28]
	add	x9,x9,x12
	ldr	x1,[sp,#17*4]		@ pull inp
	ldr	x12,[sp,#18*4]		@ pull inp+len
	add	x10,x10,x0
	add	x11,x11,x2
	stmia	x3,{x4,x5,x6,x7,x8,x9,x10,x11}
	cmp	x1,x12
	sub	x14,x14,#256	@ rewind Ktbl
	bne	.Loop

	add	sp,sp,#19*4	@ destroy frame
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r11,pc}
#else
	ldmia	sp!,{r4-r11,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	.word	0xe12fff1e			@ interoperable with Thumb ISA:-)
#endif
.size	sha256_block_data_order,.-sha256_block_data_order
#if 0
	@ start neon head
#endif
#if __ARM_MAX_ARCH__>=7
.arch	armv7-a
.fpu	neon

.global	sha256_block_data_order_neon
.type	sha256_block_data_order_neon,%function
.align	4
sha256_block_data_order_neon:
.LNEON:
	stmdb	sp!,{r4-r12,lr}

	sub	x11,sp,#16*4+16
	adrl	x14,K256
	bic	x11,x11,#15		@ align for 128-bit stores
	mov	x12,sp
	mov	sp,x11			@ alloca
	add	x2,x1,x2,lsl#6	@ len to point at the end of inp

	vld1.8		{q0},[x1]!
	vld1.8		{q1},[x1]!
	vld1.8		{q2},[x1]!
	vld1.8		{q3},[x1]!
	vld1.32		{q8},[x14,:128]! @ bits
	vld1.32		{q9},[x14,:128]!
	vld1.32		{q10},[x14,:128]!
	vld1.32		{q11},[x14,:128]!
	vrev32.8	q0,q0		@ yes, even on
	str		x0,[sp,#64]
	vrev32.8	q1,q1		@ big-endian
	str		x1,[sp,#68]
	mov		x1,sp
	vrev32.8	q2,q2
	str		x2,[sp,#72]
	vrev32.8	q3,q3
	str		x12,[sp,#76]		@ save original sp

	vadd.i32	q8,q8,q0
	vadd.i32	q9,q9,q1
	vst1.32		{q8},[x1,:128]!
	vadd.i32	q10,q10,q2
	vst1.32		{q9},[x1,:128]!
	vadd.i32	q11,q11,q3
	vst1.32		{q10},[x1,:128]!
	vst1.32		{q11},[x1,:128]!

	ldmia		x0,{x4-x11}
	sub		x1,x1,#64
	ldr		x2,[sp,#0]
	eor		x12,x12,x12
	eor		x3,x5,x6
	b		.L_00_48

.align	4
.L_00_48:
#if 0
@ Xupdate
#endif
#if 0
@ X[1..4]
#endif
	vext.8	q8,q0,q1,#4
	add	x11,x11,x2 // h+=X[i]+K[i]
	eor	x2,x9,x10
	eor	x0,x8,x8,ror#5
#if 0
@ X[9..12]
#endif
	vext.8	q9,q2,q3,#4
	add	x4,x4,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x8
	eor	x12,x0,x8,ror#19 // Sigma1(e)
	vshr.u32	q10,q8,#7
	eor	x0,x4,x4,ror#11
	eor	x2,x2,x10 // Ch(e,f,g)
#if 0
@ X[0..3] += X[9..12]
#endif
	vadd.i32	q0,q0,q9
	add	x11,x11,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x4,x5 // a^b, b^c in next round
	vshr.u32	q9,q8,#3
	eor	x0,x0,x4,ror#20 // Sigma0(a)
	add	x11,x11,x2 // h+=Ch(e,f,g)
	vsli.32	q10,q8,#25
	ldr	x2,[sp,#4]
	and	x3,x3,x12 // (b^c)&=(a^b)
	vshr.u32	q11,q8,#18
	add	x7,x7,x11 // d+=h
	add	x11,x11,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x5 // Maj(a,b,c)
	veor	q9,q9,q10
	add	x10,x10,x2 // h+=X[i]+K[i]
	vsli.32	q11,q8,#14
	eor	x2,x8,x9
	eor	x0,x7,x7,ror#5
#if 0
@ Dhi
#endif
	vshr.u32	d24,d7,#17
	add	x11,x11,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x7
#if 0
@ sigma0(X[1..4])
#endif
	veor	q9,q9,q11
	eor	x3,x0,x7,ror#19 // Sigma1(e)
	eor	x0,x11,x11,ror#11
#if 0
@ Dhi
#endif
	vsli.32	d24,d7,#15
	eor	x2,x2,x9 // Ch(e,f,g)
	add	x10,x10,x3,ror#6 // h+=Sigma1(e)
#if 0
@ Dhi
#endif
	vshr.u32	d25,d7,#10
	eor	x3,x11,x4 // a^b, b^c in next round
	eor	x0,x0,x11,ror#20 // Sigma0(a)
#if 0
@ X[0..3] += sigma0(X[1..4])
#endif
	vadd.i32	q0,q0,q9
	add	x10,x10,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#8]
	veor	d25,d25,d24
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x6,x6,x10 // d+=h
#if 0
@ Dhi
#endif
	vshr.u32	d24,d7,#19
	add	x10,x10,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x4 // Maj(a,b,c)
#if 0
@ Dhi
#endif
	vsli.32	d24,d7,#13
	add	x9,x9,x2 // h+=X[i]+K[i]
	eor	x2,x7,x8
#if 0
@ sigma1(X[14..15])
#endif
	veor	d25,d25,d24
	eor	x0,x6,x6,ror#5
	add	x10,x10,x12 // h+=Maj(a,b,c) from the past
#if 0
@ X[0..1] += sigma1(X[14..15])
#endif
#if 0
@ Dlo
#endif
#if 0
@ Dlo
#endif
	vadd.i32	d0,d0,d25
	and	x2,x2,x6
	eor	x12,x0,x6,ror#19 // Sigma1(e)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d0,#17
	eor	x0,x10,x10,ror#11
	eor	x2,x2,x8 // Ch(e,f,g)
#if 0
@ Dlo
#endif
	vsli.32	d24,d0,#15
	add	x9,x9,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x10,x11 // a^b, b^c in next round
#if 0
@ Dlo
#endif
	vshr.u32	d25,d0,#10
	eor	x0,x0,x10,ror#20 // Sigma0(a)
	add	x9,x9,x2 // h+=Ch(e,f,g)
	veor	d25,d25,d24
	ldr	x2,[sp,#12]
	and	x3,x3,x12 // (b^c)&=(a^b)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d0,#19
	add	x5,x5,x9 // d+=h
	add	x9,x9,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x11 // Maj(a,b,c)
	vld1.32	{q8},[x14,:128]!
	add	x8,x8,x2 // h+=X[i]+K[i]
#if 0
@ Dlo
#endif
	vsli.32	d24,d0,#13
	eor	x2,x6,x7
	eor	x0,x5,x5,ror#5
#if 0
@ sigma1(X[16..17])
#endif
	veor	d25,d25,d24
	add	x9,x9,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x5
#if 0
@ X[2..3] += sigma1(X[16..17])
#endif
#if 0
@ Dhi
#endif
#if 0
@ Dhi
#endif
	vadd.i32	d1,d1,d25
	eor	x3,x0,x5,ror#19 // Sigma1(e)
	eor	x0,x9,x9,ror#11
	vadd.i32	q8,q8,q0
	eor	x2,x2,x7 // Ch(e,f,g)
	add	x8,x8,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x9,x10 // a^b, b^c in next round
	eor	x0,x0,x9,ror#20 // Sigma0(a)
	add	x8,x8,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#16]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x4,x4,x8 // d+=h
	vst1.32	{q8},[x1,:128]!
	add	x8,x8,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x10 // Maj(a,b,c)
#if 0
'rotate' X[]
#endif
#if 0
@ Xupdate
#endif
#if 0
@ X[1..4]
#endif
	vext.8	q8,q1,q2,#4
	add	x7,x7,x2 // h+=X[i]+K[i]
	eor	x2,x5,x6
	eor	x0,x4,x4,ror#5
#if 0
@ X[9..12]
#endif
	vext.8	q9,q3,q0,#4
	add	x8,x8,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x4
	eor	x12,x0,x4,ror#19 // Sigma1(e)
	vshr.u32	q10,q8,#7
	eor	x0,x8,x8,ror#11
	eor	x2,x2,x6 // Ch(e,f,g)
#if 0
@ X[0..3] += X[9..12]
#endif
	vadd.i32	q1,q1,q9
	add	x7,x7,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x8,x9 // a^b, b^c in next round
	vshr.u32	q9,q8,#3
	eor	x0,x0,x8,ror#20 // Sigma0(a)
	add	x7,x7,x2 // h+=Ch(e,f,g)
	vsli.32	q10,q8,#25
	ldr	x2,[sp,#20]
	and	x3,x3,x12 // (b^c)&=(a^b)
	vshr.u32	q11,q8,#18
	add	x11,x11,x7 // d+=h
	add	x7,x7,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x9 // Maj(a,b,c)
	veor	q9,q9,q10
	add	x6,x6,x2 // h+=X[i]+K[i]
	vsli.32	q11,q8,#14
	eor	x2,x4,x5
	eor	x0,x11,x11,ror#5
#if 0
@ Dhi
#endif
	vshr.u32	d24,d1,#17
	add	x7,x7,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x11
#if 0
@ sigma0(X[1..4])
#endif
	veor	q9,q9,q11
	eor	x3,x0,x11,ror#19 // Sigma1(e)
	eor	x0,x7,x7,ror#11
#if 0
@ Dhi
#endif
	vsli.32	d24,d1,#15
	eor	x2,x2,x5 // Ch(e,f,g)
	add	x6,x6,x3,ror#6 // h+=Sigma1(e)
#if 0
@ Dhi
#endif
	vshr.u32	d25,d1,#10
	eor	x3,x7,x8 // a^b, b^c in next round
	eor	x0,x0,x7,ror#20 // Sigma0(a)
#if 0
@ X[0..3] += sigma0(X[1..4])
#endif
	vadd.i32	q1,q1,q9
	add	x6,x6,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#24]
	veor	d25,d25,d24
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x10,x10,x6 // d+=h
#if 0
@ Dhi
#endif
	vshr.u32	d24,d1,#19
	add	x6,x6,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x8 // Maj(a,b,c)
#if 0
@ Dhi
#endif
	vsli.32	d24,d1,#13
	add	x5,x5,x2 // h+=X[i]+K[i]
	eor	x2,x11,x4
#if 0
@ sigma1(X[14..15])
#endif
	veor	d25,d25,d24
	eor	x0,x10,x10,ror#5
	add	x6,x6,x12 // h+=Maj(a,b,c) from the past
#if 0
@ X[0..1] += sigma1(X[14..15])
#endif
#if 0
@ Dlo
#endif
#if 0
@ Dlo
#endif
	vadd.i32	d2,d2,d25
	and	x2,x2,x10
	eor	x12,x0,x10,ror#19 // Sigma1(e)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d2,#17
	eor	x0,x6,x6,ror#11
	eor	x2,x2,x4 // Ch(e,f,g)
#if 0
@ Dlo
#endif
	vsli.32	d24,d2,#15
	add	x5,x5,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x6,x7 // a^b, b^c in next round
#if 0
@ Dlo
#endif
	vshr.u32	d25,d2,#10
	eor	x0,x0,x6,ror#20 // Sigma0(a)
	add	x5,x5,x2 // h+=Ch(e,f,g)
	veor	d25,d25,d24
	ldr	x2,[sp,#28]
	and	x3,x3,x12 // (b^c)&=(a^b)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d2,#19
	add	x9,x9,x5 // d+=h
	add	x5,x5,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x7 // Maj(a,b,c)
	vld1.32	{q8},[x14,:128]!
	add	x4,x4,x2 // h+=X[i]+K[i]
#if 0
@ Dlo
#endif
	vsli.32	d24,d2,#13
	eor	x2,x10,x11
	eor	x0,x9,x9,ror#5
#if 0
@ sigma1(X[16..17])
#endif
	veor	d25,d25,d24
	add	x5,x5,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x9
#if 0
@ X[2..3] += sigma1(X[16..17])
#endif
#if 0
@ Dhi
#endif
#if 0
@ Dhi
#endif
	vadd.i32	d3,d3,d25
	eor	x3,x0,x9,ror#19 // Sigma1(e)
	eor	x0,x5,x5,ror#11
	vadd.i32	q8,q8,q1
	eor	x2,x2,x11 // Ch(e,f,g)
	add	x4,x4,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x5,x6 // a^b, b^c in next round
	eor	x0,x0,x5,ror#20 // Sigma0(a)
	add	x4,x4,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#32]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x8,x8,x4 // d+=h
	vst1.32	{q8},[x1,:128]!
	add	x4,x4,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x6 // Maj(a,b,c)
#if 0
'rotate' X[]
#endif
#if 0
@ Xupdate
#endif
#if 0
@ X[1..4]
#endif
	vext.8	q8,q2,q3,#4
	add	x11,x11,x2 // h+=X[i]+K[i]
	eor	x2,x9,x10
	eor	x0,x8,x8,ror#5
#if 0
@ X[9..12]
#endif
	vext.8	q9,q0,q1,#4
	add	x4,x4,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x8
	eor	x12,x0,x8,ror#19 // Sigma1(e)
	vshr.u32	q10,q8,#7
	eor	x0,x4,x4,ror#11
	eor	x2,x2,x10 // Ch(e,f,g)
#if 0
@ X[0..3] += X[9..12]
#endif
	vadd.i32	q2,q2,q9
	add	x11,x11,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x4,x5 // a^b, b^c in next round
	vshr.u32	q9,q8,#3
	eor	x0,x0,x4,ror#20 // Sigma0(a)
	add	x11,x11,x2 // h+=Ch(e,f,g)
	vsli.32	q10,q8,#25
	ldr	x2,[sp,#36]
	and	x3,x3,x12 // (b^c)&=(a^b)
	vshr.u32	q11,q8,#18
	add	x7,x7,x11 // d+=h
	add	x11,x11,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x5 // Maj(a,b,c)
	veor	q9,q9,q10
	add	x10,x10,x2 // h+=X[i]+K[i]
	vsli.32	q11,q8,#14
	eor	x2,x8,x9
	eor	x0,x7,x7,ror#5
#if 0
@ Dhi
#endif
	vshr.u32	d24,d3,#17
	add	x11,x11,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x7
#if 0
@ sigma0(X[1..4])
#endif
	veor	q9,q9,q11
	eor	x3,x0,x7,ror#19 // Sigma1(e)
	eor	x0,x11,x11,ror#11
#if 0
@ Dhi
#endif
	vsli.32	d24,d3,#15
	eor	x2,x2,x9 // Ch(e,f,g)
	add	x10,x10,x3,ror#6 // h+=Sigma1(e)
#if 0
@ Dhi
#endif
	vshr.u32	d25,d3,#10
	eor	x3,x11,x4 // a^b, b^c in next round
	eor	x0,x0,x11,ror#20 // Sigma0(a)
#if 0
@ X[0..3] += sigma0(X[1..4])
#endif
	vadd.i32	q2,q2,q9
	add	x10,x10,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#40]
	veor	d25,d25,d24
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x6,x6,x10 // d+=h
#if 0
@ Dhi
#endif
	vshr.u32	d24,d3,#19
	add	x10,x10,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x4 // Maj(a,b,c)
#if 0
@ Dhi
#endif
	vsli.32	d24,d3,#13
	add	x9,x9,x2 // h+=X[i]+K[i]
	eor	x2,x7,x8
#if 0
@ sigma1(X[14..15])
#endif
	veor	d25,d25,d24
	eor	x0,x6,x6,ror#5
	add	x10,x10,x12 // h+=Maj(a,b,c) from the past
#if 0
@ X[0..1] += sigma1(X[14..15])
#endif
#if 0
@ Dlo
#endif
#if 0
@ Dlo
#endif
	vadd.i32	d4,d4,d25
	and	x2,x2,x6
	eor	x12,x0,x6,ror#19 // Sigma1(e)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d4,#17
	eor	x0,x10,x10,ror#11
	eor	x2,x2,x8 // Ch(e,f,g)
#if 0
@ Dlo
#endif
	vsli.32	d24,d4,#15
	add	x9,x9,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x10,x11 // a^b, b^c in next round
#if 0
@ Dlo
#endif
	vshr.u32	d25,d4,#10
	eor	x0,x0,x10,ror#20 // Sigma0(a)
	add	x9,x9,x2 // h+=Ch(e,f,g)
	veor	d25,d25,d24
	ldr	x2,[sp,#44]
	and	x3,x3,x12 // (b^c)&=(a^b)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d4,#19
	add	x5,x5,x9 // d+=h
	add	x9,x9,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x11 // Maj(a,b,c)
	vld1.32	{q8},[x14,:128]!
	add	x8,x8,x2 // h+=X[i]+K[i]
#if 0
@ Dlo
#endif
	vsli.32	d24,d4,#13
	eor	x2,x6,x7
	eor	x0,x5,x5,ror#5
#if 0
@ sigma1(X[16..17])
#endif
	veor	d25,d25,d24
	add	x9,x9,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x5
#if 0
@ X[2..3] += sigma1(X[16..17])
#endif
#if 0
@ Dhi
#endif
#if 0
@ Dhi
#endif
	vadd.i32	d5,d5,d25
	eor	x3,x0,x5,ror#19 // Sigma1(e)
	eor	x0,x9,x9,ror#11
	vadd.i32	q8,q8,q2
	eor	x2,x2,x7 // Ch(e,f,g)
	add	x8,x8,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x9,x10 // a^b, b^c in next round
	eor	x0,x0,x9,ror#20 // Sigma0(a)
	add	x8,x8,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#48]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x4,x4,x8 // d+=h
	vst1.32	{q8},[x1,:128]!
	add	x8,x8,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x10 // Maj(a,b,c)
#if 0
'rotate' X[]
#endif
#if 0
@ Xupdate
#endif
#if 0
@ X[1..4]
#endif
	vext.8	q8,q3,q0,#4
	add	x7,x7,x2 // h+=X[i]+K[i]
	eor	x2,x5,x6
	eor	x0,x4,x4,ror#5
#if 0
@ X[9..12]
#endif
	vext.8	q9,q1,q2,#4
	add	x8,x8,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x4
	eor	x12,x0,x4,ror#19 // Sigma1(e)
	vshr.u32	q10,q8,#7
	eor	x0,x8,x8,ror#11
	eor	x2,x2,x6 // Ch(e,f,g)
#if 0
@ X[0..3] += X[9..12]
#endif
	vadd.i32	q3,q3,q9
	add	x7,x7,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x8,x9 // a^b, b^c in next round
	vshr.u32	q9,q8,#3
	eor	x0,x0,x8,ror#20 // Sigma0(a)
	add	x7,x7,x2 // h+=Ch(e,f,g)
	vsli.32	q10,q8,#25
	ldr	x2,[sp,#52]
	and	x3,x3,x12 // (b^c)&=(a^b)
	vshr.u32	q11,q8,#18
	add	x11,x11,x7 // d+=h
	add	x7,x7,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x9 // Maj(a,b,c)
	veor	q9,q9,q10
	add	x6,x6,x2 // h+=X[i]+K[i]
	vsli.32	q11,q8,#14
	eor	x2,x4,x5
	eor	x0,x11,x11,ror#5
#if 0
@ Dhi
#endif
	vshr.u32	d24,d5,#17
	add	x7,x7,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x11
#if 0
@ sigma0(X[1..4])
#endif
	veor	q9,q9,q11
	eor	x3,x0,x11,ror#19 // Sigma1(e)
	eor	x0,x7,x7,ror#11
#if 0
@ Dhi
#endif
	vsli.32	d24,d5,#15
	eor	x2,x2,x5 // Ch(e,f,g)
	add	x6,x6,x3,ror#6 // h+=Sigma1(e)
#if 0
@ Dhi
#endif
	vshr.u32	d25,d5,#10
	eor	x3,x7,x8 // a^b, b^c in next round
	eor	x0,x0,x7,ror#20 // Sigma0(a)
#if 0
@ X[0..3] += sigma0(X[1..4])
#endif
	vadd.i32	q3,q3,q9
	add	x6,x6,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#56]
	veor	d25,d25,d24
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x10,x10,x6 // d+=h
#if 0
@ Dhi
#endif
	vshr.u32	d24,d5,#19
	add	x6,x6,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x8 // Maj(a,b,c)
#if 0
@ Dhi
#endif
	vsli.32	d24,d5,#13
	add	x5,x5,x2 // h+=X[i]+K[i]
	eor	x2,x11,x4
#if 0
@ sigma1(X[14..15])
#endif
	veor	d25,d25,d24
	eor	x0,x10,x10,ror#5
	add	x6,x6,x12 // h+=Maj(a,b,c) from the past
#if 0
@ X[0..1] += sigma1(X[14..15])
#endif
#if 0
@ Dlo
#endif
#if 0
@ Dlo
#endif
	vadd.i32	d6,d6,d25
	and	x2,x2,x10
	eor	x12,x0,x10,ror#19 // Sigma1(e)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d6,#17
	eor	x0,x6,x6,ror#11
	eor	x2,x2,x4 // Ch(e,f,g)
#if 0
@ Dlo
#endif
	vsli.32	d24,d6,#15
	add	x5,x5,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x6,x7 // a^b, b^c in next round
#if 0
@ Dlo
#endif
	vshr.u32	d25,d6,#10
	eor	x0,x0,x6,ror#20 // Sigma0(a)
	add	x5,x5,x2 // h+=Ch(e,f,g)
	veor	d25,d25,d24
	ldr	x2,[sp,#60]
	and	x3,x3,x12 // (b^c)&=(a^b)
#if 0
@ Dlo
#endif
	vshr.u32	d24,d6,#19
	add	x9,x9,x5 // d+=h
	add	x5,x5,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x7 // Maj(a,b,c)
	vld1.32	{q8},[x14,:128]!
	add	x4,x4,x2 // h+=X[i]+K[i]
#if 0
@ Dlo
#endif
	vsli.32	d24,d6,#13
	eor	x2,x10,x11
	eor	x0,x9,x9,ror#5
#if 0
@ sigma1(X[16..17])
#endif
	veor	d25,d25,d24
	add	x5,x5,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x9
#if 0
@ X[2..3] += sigma1(X[16..17])
#endif
#if 0
@ Dhi
#endif
#if 0
@ Dhi
#endif
	vadd.i32	d7,d7,d25
	eor	x3,x0,x9,ror#19 // Sigma1(e)
	eor	x0,x5,x5,ror#11
	vadd.i32	q8,q8,q3
	eor	x2,x2,x11 // Ch(e,f,g)
	add	x4,x4,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x5,x6 // a^b, b^c in next round
	eor	x0,x0,x5,ror#20 // Sigma0(a)
	add	x4,x4,x2 // h+=Ch(e,f,g)
	ldr	x2,[x14]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x8,x8,x4 // d+=h
	vst1.32	{q8},[x1,:128]!
	add	x4,x4,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x6 // Maj(a,b,c)
#if 0
'rotate' X[]
#endif
#if 0
	@ after 4 Xupdates
#endif
	teq	x2,#0				@ check for K256 terminator
	ldr	x2,[sp,#0]
	sub	x1,x1,#64
	bne	.L_00_48

	ldr		x1,[sp,#68]
	ldr		x0,[sp,#72]
	sub		x14,x14,#256	@ rewind x14
	teq		x1,x0
	it		eq
	subeq		x1,x1,#64		@ avoid SEGV
	vld1.8		{q0},[x1]!		@ load next input block
	vld1.8		{q1},[x1]!
	vld1.8		{q2},[x1]!
	vld1.8		{q3},[x1]!
	it		ne
	strne		x1,[sp,#68]
	mov		x1,sp
#if 0
@ Xpreload
#endif
	add	x11,x11,x2 // h+=X[i]+K[i]
	eor	x2,x9,x10
	eor	x0,x8,x8,ror#5
	add	x4,x4,x12 // h+=Maj(a,b,c) from the past
	vld1.32	{q8},[x14,:128]!
	and	x2,x2,x8
	eor	x12,x0,x8,ror#19 // Sigma1(e)
	eor	x0,x4,x4,ror#11
	eor	x2,x2,x10 // Ch(e,f,g)
	vrev32.8	q0,q0
	add	x11,x11,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x4,x5 // a^b, b^c in next round
	eor	x0,x0,x4,ror#20 // Sigma0(a)
	add	x11,x11,x2 // h+=Ch(e,f,g)
	vadd.i32	q8,q8,q0
#if 0
@ remaining insn
#endif
	ldr	x2,[sp,#4]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x7,x7,x11 // d+=h
	add	x11,x11,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x5 // Maj(a,b,c)
	add	x10,x10,x2 // h+=X[i]+K[i]
	eor	x2,x8,x9
	eor	x0,x7,x7,ror#5
	add	x11,x11,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x7
	eor	x3,x0,x7,ror#19 // Sigma1(e)
	eor	x0,x11,x11,ror#11
	eor	x2,x2,x9 // Ch(e,f,g)
	add	x10,x10,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x11,x4 // a^b, b^c in next round
	eor	x0,x0,x11,ror#20 // Sigma0(a)
	add	x10,x10,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#8]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x6,x6,x10 // d+=h
	add	x10,x10,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x4 // Maj(a,b,c)
	add	x9,x9,x2 // h+=X[i]+K[i]
	eor	x2,x7,x8
	eor	x0,x6,x6,ror#5
	add	x10,x10,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x6
	eor	x12,x0,x6,ror#19 // Sigma1(e)
	eor	x0,x10,x10,ror#11
	eor	x2,x2,x8 // Ch(e,f,g)
	add	x9,x9,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x10,x11 // a^b, b^c in next round
	eor	x0,x0,x10,ror#20 // Sigma0(a)
	add	x9,x9,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#12]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x5,x5,x9 // d+=h
	add	x9,x9,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x11 // Maj(a,b,c)
	add	x8,x8,x2 // h+=X[i]+K[i]
	eor	x2,x6,x7
	eor	x0,x5,x5,ror#5
	add	x9,x9,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x5
	eor	x3,x0,x5,ror#19 // Sigma1(e)
	eor	x0,x9,x9,ror#11
	eor	x2,x2,x7 // Ch(e,f,g)
	add	x8,x8,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x9,x10 // a^b, b^c in next round
	eor	x0,x0,x9,ror#20 // Sigma0(a)
	add	x8,x8,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#16]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x4,x4,x8 // d+=h
	add	x8,x8,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x10 // Maj(a,b,c)
	vst1.32	{q8},[x1,:128]!
#if 0
@ Xpreload 'rotate' X[]
#endif
#if 0
@ Xpreload
#endif
	add	x7,x7,x2 // h+=X[i]+K[i]
	eor	x2,x5,x6
	eor	x0,x4,x4,ror#5
	add	x8,x8,x12 // h+=Maj(a,b,c) from the past
	vld1.32	{q8},[x14,:128]!
	and	x2,x2,x4
	eor	x12,x0,x4,ror#19 // Sigma1(e)
	eor	x0,x8,x8,ror#11
	eor	x2,x2,x6 // Ch(e,f,g)
	vrev32.8	q1,q1
	add	x7,x7,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x8,x9 // a^b, b^c in next round
	eor	x0,x0,x8,ror#20 // Sigma0(a)
	add	x7,x7,x2 // h+=Ch(e,f,g)
	vadd.i32	q8,q8,q1
#if 0
@ remaining insn
#endif
	ldr	x2,[sp,#20]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x11,x11,x7 // d+=h
	add	x7,x7,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x9 // Maj(a,b,c)
	add	x6,x6,x2 // h+=X[i]+K[i]
	eor	x2,x4,x5
	eor	x0,x11,x11,ror#5
	add	x7,x7,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x11
	eor	x3,x0,x11,ror#19 // Sigma1(e)
	eor	x0,x7,x7,ror#11
	eor	x2,x2,x5 // Ch(e,f,g)
	add	x6,x6,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x7,x8 // a^b, b^c in next round
	eor	x0,x0,x7,ror#20 // Sigma0(a)
	add	x6,x6,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#24]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x10,x10,x6 // d+=h
	add	x6,x6,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x8 // Maj(a,b,c)
	add	x5,x5,x2 // h+=X[i]+K[i]
	eor	x2,x11,x4
	eor	x0,x10,x10,ror#5
	add	x6,x6,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x10
	eor	x12,x0,x10,ror#19 // Sigma1(e)
	eor	x0,x6,x6,ror#11
	eor	x2,x2,x4 // Ch(e,f,g)
	add	x5,x5,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x6,x7 // a^b, b^c in next round
	eor	x0,x0,x6,ror#20 // Sigma0(a)
	add	x5,x5,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#28]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x9,x9,x5 // d+=h
	add	x5,x5,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x7 // Maj(a,b,c)
	add	x4,x4,x2 // h+=X[i]+K[i]
	eor	x2,x10,x11
	eor	x0,x9,x9,ror#5
	add	x5,x5,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x9
	eor	x3,x0,x9,ror#19 // Sigma1(e)
	eor	x0,x5,x5,ror#11
	eor	x2,x2,x11 // Ch(e,f,g)
	add	x4,x4,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x5,x6 // a^b, b^c in next round
	eor	x0,x0,x5,ror#20 // Sigma0(a)
	add	x4,x4,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#32]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x8,x8,x4 // d+=h
	add	x4,x4,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x6 // Maj(a,b,c)
	vst1.32	{q8},[x1,:128]!
#if 0
@ Xpreload 'rotate' X[]
#endif
#if 0
@ Xpreload
#endif
	add	x11,x11,x2 // h+=X[i]+K[i]
	eor	x2,x9,x10
	eor	x0,x8,x8,ror#5
	add	x4,x4,x12 // h+=Maj(a,b,c) from the past
	vld1.32	{q8},[x14,:128]!
	and	x2,x2,x8
	eor	x12,x0,x8,ror#19 // Sigma1(e)
	eor	x0,x4,x4,ror#11
	eor	x2,x2,x10 // Ch(e,f,g)
	vrev32.8	q2,q2
	add	x11,x11,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x4,x5 // a^b, b^c in next round
	eor	x0,x0,x4,ror#20 // Sigma0(a)
	add	x11,x11,x2 // h+=Ch(e,f,g)
	vadd.i32	q8,q8,q2
#if 0
@ remaining insn
#endif
	ldr	x2,[sp,#36]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x7,x7,x11 // d+=h
	add	x11,x11,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x5 // Maj(a,b,c)
	add	x10,x10,x2 // h+=X[i]+K[i]
	eor	x2,x8,x9
	eor	x0,x7,x7,ror#5
	add	x11,x11,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x7
	eor	x3,x0,x7,ror#19 // Sigma1(e)
	eor	x0,x11,x11,ror#11
	eor	x2,x2,x9 // Ch(e,f,g)
	add	x10,x10,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x11,x4 // a^b, b^c in next round
	eor	x0,x0,x11,ror#20 // Sigma0(a)
	add	x10,x10,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#40]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x6,x6,x10 // d+=h
	add	x10,x10,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x4 // Maj(a,b,c)
	add	x9,x9,x2 // h+=X[i]+K[i]
	eor	x2,x7,x8
	eor	x0,x6,x6,ror#5
	add	x10,x10,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x6
	eor	x12,x0,x6,ror#19 // Sigma1(e)
	eor	x0,x10,x10,ror#11
	eor	x2,x2,x8 // Ch(e,f,g)
	add	x9,x9,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x10,x11 // a^b, b^c in next round
	eor	x0,x0,x10,ror#20 // Sigma0(a)
	add	x9,x9,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#44]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x5,x5,x9 // d+=h
	add	x9,x9,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x11 // Maj(a,b,c)
	add	x8,x8,x2 // h+=X[i]+K[i]
	eor	x2,x6,x7
	eor	x0,x5,x5,ror#5
	add	x9,x9,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x5
	eor	x3,x0,x5,ror#19 // Sigma1(e)
	eor	x0,x9,x9,ror#11
	eor	x2,x2,x7 // Ch(e,f,g)
	add	x8,x8,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x9,x10 // a^b, b^c in next round
	eor	x0,x0,x9,ror#20 // Sigma0(a)
	add	x8,x8,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#48]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x4,x4,x8 // d+=h
	add	x8,x8,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x10 // Maj(a,b,c)
	vst1.32	{q8},[x1,:128]!
#if 0
@ Xpreload 'rotate' X[]
#endif
#if 0
@ Xpreload
#endif
	add	x7,x7,x2 // h+=X[i]+K[i]
	eor	x2,x5,x6
	eor	x0,x4,x4,ror#5
	add	x8,x8,x12 // h+=Maj(a,b,c) from the past
	vld1.32	{q8},[x14,:128]!
	and	x2,x2,x4
	eor	x12,x0,x4,ror#19 // Sigma1(e)
	eor	x0,x8,x8,ror#11
	eor	x2,x2,x6 // Ch(e,f,g)
	vrev32.8	q3,q3
	add	x7,x7,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x8,x9 // a^b, b^c in next round
	eor	x0,x0,x8,ror#20 // Sigma0(a)
	add	x7,x7,x2 // h+=Ch(e,f,g)
	vadd.i32	q8,q8,q3
#if 0
@ remaining insn
#endif
	ldr	x2,[sp,#52]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x11,x11,x7 // d+=h
	add	x7,x7,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x9 // Maj(a,b,c)
	add	x6,x6,x2 // h+=X[i]+K[i]
	eor	x2,x4,x5
	eor	x0,x11,x11,ror#5
	add	x7,x7,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x11
	eor	x3,x0,x11,ror#19 // Sigma1(e)
	eor	x0,x7,x7,ror#11
	eor	x2,x2,x5 // Ch(e,f,g)
	add	x6,x6,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x7,x8 // a^b, b^c in next round
	eor	x0,x0,x7,ror#20 // Sigma0(a)
	add	x6,x6,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#56]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x10,x10,x6 // d+=h
	add	x6,x6,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x8 // Maj(a,b,c)
	add	x5,x5,x2 // h+=X[i]+K[i]
	eor	x2,x11,x4
	eor	x0,x10,x10,ror#5
	add	x6,x6,x12 // h+=Maj(a,b,c) from the past
	and	x2,x2,x10
	eor	x12,x0,x10,ror#19 // Sigma1(e)
	eor	x0,x6,x6,ror#11
	eor	x2,x2,x4 // Ch(e,f,g)
	add	x5,x5,x12,ror#6 // h+=Sigma1(e)
	eor	x12,x6,x7 // a^b, b^c in next round
	eor	x0,x0,x6,ror#20 // Sigma0(a)
	add	x5,x5,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#60]
	and	x3,x3,x12 // (b^c)&=(a^b)
	add	x9,x9,x5 // d+=h
	add	x5,x5,x0,ror#2 // h+=Sigma0(a)
	eor	x3,x3,x7 // Maj(a,b,c)
	add	x4,x4,x2 // h+=X[i]+K[i]
	eor	x2,x10,x11
	eor	x0,x9,x9,ror#5
	add	x5,x5,x3 // h+=Maj(a,b,c) from the past
	and	x2,x2,x9
	eor	x3,x0,x9,ror#19 // Sigma1(e)
	eor	x0,x5,x5,ror#11
	eor	x2,x2,x11 // Ch(e,f,g)
	add	x4,x4,x3,ror#6 // h+=Sigma1(e)
	eor	x3,x5,x6 // a^b, b^c in next round
	eor	x0,x0,x5,ror#20 // Sigma0(a)
	add	x4,x4,x2 // h+=Ch(e,f,g)
	ldr	x2,[sp,#64]
	and	x12,x12,x3 // (b^c)&=(a^b)
	add	x8,x8,x4 // d+=h
	add	x4,x4,x0,ror#2 // h+=Sigma0(a)
	eor	x12,x12,x6 // Maj(a,b,c)
	vst1.32	{q8},[x1,:128]!
#if 0
@ Xpreload 'rotate' X[]
#endif
#if 0
	@ after 4 Xpreloads
#endif
	ldr	x0,[x2,#0]
	add	x4,x4,x12			@ h+=Maj(a,b,c) from the past
	ldr	x12,[x2,#4]
	ldr	x3,[x2,#8]
	ldr	x1,[x2,#12]
	add	x4,x4,x0			@ accumulate
	ldr	x0,[x2,#16]
	add	x5,x5,x12
	ldr	x12,[x2,#20]
	add	x6,x6,x3
	ldr	x3,[x2,#24]
	add	x7,x7,x1
	ldr	x1,[x2,#28]
	add	x8,x8,x0
	str	x4,[x2],#4
	add	x9,x9,x12
	str	x5,[x2],#4
	add	x10,x10,x3
	str	x6,[x2],#4
	add	x11,x11,x1
	str	x7,[x2],#4
	stmia	x2,{x8-x11}

	ittte	ne
	movne	x1,sp
	ldrne	x2,[sp,#0]
	eorne	x12,x12,x12
	ldreq	sp,[sp,#76]			@ restore original sp
	itt	ne
	eorne	x3,x5,x6
	bne	.L_00_48

	ldmia	sp!,{r4-r12,pc}
.size	sha256_block_data_order_neon,.-sha256_block_data_order_neon
#endif
#if 0
	@ ARMv8 stuff
#endif
#if __ARM_MAX_ARCH__>=7 && !defined(__KERNEL__)

# ifdef __thumb2__
#  define INST(a,b,c,d)	.byte	c,d|0xc,a,b
# else
#  define INST(a,b,c,d)	.byte	a,b,c,d
# endif

.type	sha256_block_data_order_armv8,%function
.align	5
sha256_block_data_order_armv8:
.LARMv8:
	vld1.32	{q0,q1},[x0]
# ifdef __thumb2__
	adr	r3,.LARMv8
	sub	r3,r3,#.LARMv8-K256
# else
	adrl	r3,K256
# endif
	add	x2,x1,x2,lsl#6	@ len to point at the end of inp

.Loop_v8:
	vld1.8		{q8-q9},[x1]!
	vld1.8		{q10-q11},[x1]!
	vld1.32		{q12},[r3]!
	vrev32.8	q8,q8
	vrev32.8	q9,q9
	vrev32.8	q10,q10
	vrev32.8	q11,q11
	vmov		q14,q0	@ offload
	vmov		q15,q1
	teq		x1,x2
#if 0
	@ 0+1 of 12 rounds
#endif
	vld1.32		{q13},[r3]!
	vadd.i32	q12,q12,q8
	INST(0xe2,0x03,0xfa,0xf3)	@ sha256su0 q8,q9
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12
	INST(0xe6,0x0c,0x64,0xf3)	@ sha256su1 q8,q10,q11
#if 0
	@ 1+1 of 12 rounds
#endif
	vld1.32		{q12},[r3]!
	vadd.i32	q13,q13,q9
	INST(0xe4,0x23,0xfa,0xf3)	@ sha256su0 q9,q10
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13
	INST(0xe0,0x2c,0x66,0xf3)	@ sha256su1 q9,q11,q8
#if 0
	@ 2+1 of 12 rounds
#endif
	vld1.32		{q13},[r3]!
	vadd.i32	q12,q12,q10
	INST(0xe6,0x43,0xfa,0xf3)	@ sha256su0 q10,q11
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12
	INST(0xe2,0x4c,0x60,0xf3)	@ sha256su1 q10,q8,q9
#if 0
	@ 3+1 of 12 rounds
#endif
	vld1.32		{q12},[r3]!
	vadd.i32	q13,q13,q11
	INST(0xe0,0x63,0xfa,0xf3)	@ sha256su0 q11,q8
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13
	INST(0xe4,0x6c,0x62,0xf3)	@ sha256su1 q11,q9,q10
#if 0
	@ 4+1 of 12 rounds
#endif
	vld1.32		{q13},[r3]!
	vadd.i32	q12,q12,q8
	INST(0xe2,0x03,0xfa,0xf3)	@ sha256su0 q8,q9
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12
	INST(0xe6,0x0c,0x64,0xf3)	@ sha256su1 q8,q10,q11
#if 0
	@ 5+1 of 12 rounds
#endif
	vld1.32		{q12},[r3]!
	vadd.i32	q13,q13,q9
	INST(0xe4,0x23,0xfa,0xf3)	@ sha256su0 q9,q10
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13
	INST(0xe0,0x2c,0x66,0xf3)	@ sha256su1 q9,q11,q8
#if 0
	@ 6+1 of 12 rounds
#endif
	vld1.32		{q13},[r3]!
	vadd.i32	q12,q12,q10
	INST(0xe6,0x43,0xfa,0xf3)	@ sha256su0 q10,q11
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12
	INST(0xe2,0x4c,0x60,0xf3)	@ sha256su1 q10,q8,q9
#if 0
	@ 7+1 of 12 rounds
#endif
	vld1.32		{q12},[r3]!
	vadd.i32	q13,q13,q11
	INST(0xe0,0x63,0xfa,0xf3)	@ sha256su0 q11,q8
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13
	INST(0xe4,0x6c,0x62,0xf3)	@ sha256su1 q11,q9,q10
#if 0
	@ 8+1 of 12 rounds
#endif
	vld1.32		{q13},[r3]!
	vadd.i32	q12,q12,q8
	INST(0xe2,0x03,0xfa,0xf3)	@ sha256su0 q8,q9
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12
	INST(0xe6,0x0c,0x64,0xf3)	@ sha256su1 q8,q10,q11
#if 0
	@ 9+1 of 12 rounds
#endif
	vld1.32		{q12},[r3]!
	vadd.i32	q13,q13,q9
	INST(0xe4,0x23,0xfa,0xf3)	@ sha256su0 q9,q10
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13
	INST(0xe0,0x2c,0x66,0xf3)	@ sha256su1 q9,q11,q8
#if 0
	@ 10+1 of 12 rounds
#endif
	vld1.32		{q13},[r3]!
	vadd.i32	q12,q12,q10
	INST(0xe6,0x43,0xfa,0xf3)	@ sha256su0 q10,q11
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12
	INST(0xe2,0x4c,0x60,0xf3)	@ sha256su1 q10,q8,q9
#if 0
	@ 11+1 of 12 rounds
#endif
	vld1.32		{q12},[r3]!
	vadd.i32	q13,q13,q11
	INST(0xe0,0x63,0xfa,0xf3)	@ sha256su0 q11,q8
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13
	INST(0xe4,0x6c,0x62,0xf3)	@ sha256su1 q11,q9,q10
#if 0
	@ below 12 rounds
#endif
	vld1.32		{q13},[r3]!
	vadd.i32	q12,q12,q8
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12

	vld1.32		{q12},[r3]!
	vadd.i32	q13,q13,q9
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13

	vld1.32		{q13},[r3]
	vadd.i32	q12,q12,q10
	sub		r3,r3,#256-16	@ rewind
	vmov		q2,q0
	INST(0x68,0x0c,0x02,0xf3)	@ sha256h q0,q1,q12
	INST(0x68,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q12

	vadd.i32	q13,q13,q11
	vmov		q2,q0
	INST(0x6a,0x0c,0x02,0xf3)	@ sha256h q0,q1,q13
	INST(0x6a,0x2c,0x14,0xf3)	@ sha256h2 q1,q2,q13

	vadd.i32	q0,q0,q14
	vadd.i32	q1,q1,q15
	it		ne
	bne		.Loop_v8

	vst1.32		{q0,q1},[x0]

	bx	lr		@ bx lr
.size	sha256_block_data_order_armv8,.-sha256_block_data_order_armv8
#endif
#if 0
	@ ARMv8 tail
#endif
.asciz  "SHA256 block transform for ARMv4/NEON/ARMv8, CRYPTOGAMS by <appro@openssl.org>"
.align	2
#if __ARM_MAX_ARCH__>=7 && !defined(__KERNEL__)
.comm   OPENSSL_armcap_P,4,4
#endif
