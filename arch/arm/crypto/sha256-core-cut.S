/*
 * sha2-neon-core.S - core SHA-224/SHA-256 transform using v8 Crypto Extensions
 *
 * Copyright (C) 2016 Linaro Ltd <daniel.thompson@linaro.org>
 * Copyright (C) 2016 Linaro Ltd <victor.chong@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

	.text
	.arch	armv8-a+simd

	/*
	 * The SHA-256 round constants
	 */
	.align	4
.LK256:
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

	/*
	 * void sha256_block_data_order_neon(u32 *digest, const void *data,
	 *						 unsigned int num_blks);
	 */
	/*
	 * void sha2_neon_transform(struct sha256_ce_state *sst, u8 const *src,
	 *			  int blocks)
	 */
ENTRY(sha256_neon_transform)

	//ldmia, stmia no equivs in aarch64!

	stmdb	sp!,{r4-r12,lr}

	sub	x11,sp,#16*4+16
	adrl	x14,K256
	bic	x11,x11,#15		@ align for 128-bit stores
	mov	x12,sp
	mov	sp,x11			@ alloca
	add	x2,x1,x2,lsl#6	@ len to point at the end of inp

	/* load input - blk1 */
	vld1.8		{q0},[x1]!
	vld1.8		{q1},[x1]!
	vld1.8		{q2},[x1]!
	vld1.8		{q3},[x1]!

	// STR{<c>}{<q>} <Rt>, [<Rn> {, #+/-<imm>}]  Offset: index==TRUE, wback==FALSE
	// STR{<c>}{<q>} <Rt>, [<Rn>, #+/-<imm>]!	 Pre-indexed: index==TRUE, wback==TRUE
 	// STR{<c>}{<q>} <Rt>, [<Rn>], #+/-<imm> Post-indexed: index==FALSE, wback==TRUE

	/* load 1st 16 round constants */
	vld1.32 	{q8},[x14,:128]! // 128b = 16 bytes, 4 lanes * 32b per lane
	vld1.32 	{q9},[x14,:128]! // 128b = 16 bytes
	vld1.32 	{q10},[x14,:128]! // 128b = 16 bytes
	vld1.32 	{q11},[x14,:128]! // 128b = 16 bytes
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

	ret
ENDPROC(sha256_neon_transform)
