#!/usr/bin/env perl

#
# AArch64 port of the OpenSSL SHA256 implementation for ARM NEON
#
# Copyright (c) 2016 Linaro Ltd. <ard.biesheuvel@linaro.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
#
# Permission to use under GPL terms is granted.
# ====================================================================

# SHA256 block procedure for ARMv4. May 2007.

# Performance is ~2x better than gcc 3.4 generated code and in "abso-
# lute" terms is ~2250 cycles per 64-byte block or ~35 cycles per
# byte [on single-issue Xscale PXA250 core].

# July 2010.
#
# Rescheduling for dual-issue pipeline resulted in 22% improvement on
# Cortex A8 core and ~20 cycles per processed byte.

# February 2011.
#
# Profiler-assisted and platform-specific optimization resulted in 16%
# improvement on Cortex A8 core and ~15.4 cycles per processed byte.

# September 2013.
#
# Add NEON implementation. On Cortex A8 it was measured to process one
# byte in 12.5 cycles or 23% faster than integer-only code. Snapdragon
# S4 does it in 12.5 cycles too, but it's 50% faster than integer-only
# code (meaning that latter performs sub-optimally, nothing was done
# about it).

# May 2014.
#
# Add ARMv8 code path performing at 2.0 cpb on Apple A7.

while (($output=shift) && ($output!~/^\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$ctx="x0";	$t0="w0";	$xt0="x0";
$inp="x1";	$t4="w1";	$xt4="x1";
$len="x2";	$t1="w2";	$xt1="x2";
		$t3="w3";
$A="w4";
$B="w5";
$C="w6";
$D="w7";
$E="w8";
$F="w9";
$G="w10";
$H="w11";
@V=($A,$B,$C,$D,$E,$F,$G,$H);
$t2="w12";
$xt2="x12";
$Ktbl="x14";

@Sigma0=( 2,13,22);
@Sigma1=( 6,11,25);
@sigma0=( 7,18, 3);
@sigma1=(17,19,10);

######################################################################
# NEON stuff
#
{{{
my @VB=map("v$_.16b",(0..3));
my @VS=map("v$_.4s",(0..3));

my ($TS0,$TS1,$TS2,$TS3,$TS4,$TS5,$TS6,$TS7)=("v4.4s","v5.4s","v6.4s","v7.4s","v8.4s","v9.4s","v10.4s","v11.4s");
my ($TB0,$TB1,$TB2,$TB3,$TB4,$TB5,$TB6,$TB7)=("v4.16b","v5.16b","v6.16b","v7.16b","v8.16b","v9.16b","v10.16b","v11.16b");
my ($TD5HI,$TD5LO,$TD7LO)=("v9.d[1]", "d9", "v11.d[0]");
my $Xfer=$xt4;
my $j=0;

sub AUTOLOAD()          # thunk [simplified] x86-style perlasm
{ my $opcode = $AUTOLOAD; $opcode =~ s/.*:://; $opcode =~ s/_/\./;
  my $arg = pop;
    $arg = "#$arg" if ($arg*1 eq $arg);
    $code .= "\t$opcode\t".join(',',@_,$arg)."\n";
}

sub Xupdate()
{ use integer;
  my $body = shift;
  my @insns = (&$body,&$body,&$body,&$body);
  my ($a,$b,$c,$d,$e,$f,$g,$h);

	&ext		($TB0,@VB[0],@VB[1],4);	# X[1..4]
	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	&ext		($TB1,@VB[2],@VB[3],4);	# X[9..12]
	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	&ushr		($TS2,$TS0,$sigma0[0]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&add 		(@VS[0],@VS[0],$TS1);	# X[0..3] += X[9..12]
	 eval(shift(@insns));
	 eval(shift(@insns));
	&ushr		($TS1,$TS0,$sigma0[2]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&sli		($TS2,$TS0,32-$sigma0[0]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&ushr		($TS3,$TS0,$sigma0[1]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&eor		($TB1,$TB1,$TB2);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&sli		($TS3,$TS0,32-$sigma0[1]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &ushr		($TS4,@VS[3],$sigma1[0]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&eor		($TB1,$TB1,$TB3);	# sigma0(X[1..4])
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &sli		($TS4,@VS[3],32-$sigma1[0]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &ushr		($TS5,@VS[3],$sigma1[2]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&add		(@VS[0],@VS[0],$TS1);	# X[0..3] += sigma0(X[1..4])
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &eor		($TB5,$TB5,$TB4);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &ushr		($TS4,@VS[3],$sigma1[1]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &sli		($TS4,@VS[3],32-$sigma1[1]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &eor		($TB5,$TB5,$TB4);	# sigma1(X[14..15])
	 eval(shift(@insns));
	 eval(shift(@insns));
	&mov		($TD5LO, $TD5HI);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&add		(@VS[0],@VS[0],$TS5);	# X[0..1] += sigma1(X[14..15])
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &ushr		($TS6,@VS[0],$sigma1[0]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &sli		($TS6,@VS[0],32-$sigma1[0]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &ushr		($TS7,@VS[0],$sigma1[2]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &eor		($TB7,$TB7,$TB6);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &ushr		($TS6,@VS[0],$sigma1[1]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&ld1		("{$TS0}","[$Ktbl], #16");
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &sli		($TS6,@VS[0],32-$sigma1[1]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	  &eor		($TB7,$TB7,$TB6);	# sigma1(X[16..17])
	 eval(shift(@insns));
	 eval(shift(@insns));
	&eor		($TB5,$TB5,$TB5);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&mov		($TD5HI, $TD7LO);
	 eval(shift(@insns));
	 eval(shift(@insns));
	&add		(@VS[0],@VS[0],$TS5);	# X[0..3] += sigma1(X[14..17])
	 eval(shift(@insns));
	 eval(shift(@insns));
	&add		($TS0,$TS0,@VS[0]);
	 while($#insns>=2) { eval(shift(@insns)); }
	&st1		("{$TS0}","[$Xfer], #16");
	 eval(shift(@insns));
	 eval(shift(@insns));

	push(@VB,shift(@VB));		# "rotate" X[]
	push(@VS,shift(@VS));		# "rotate" X[]
}

sub Xpreload()
{ use integer;
  my $body = shift;
  my @insns = (&$body,&$body,&$body,&$body);
  my ($a,$b,$c,$d,$e,$f,$g,$h);

	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	&ld1		("{$TS0}","[$Ktbl], #16");
	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	&rev32		(@VB[0],@VB[0]);
	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	 eval(shift(@insns));
	&add		($TS0,$TS0,@VS[0]);
	 foreach (@insns) { eval; }	# remaining instructions
	&st1		("{$TS0}","[$Xfer], #16");

	push(@VB,shift(@VB));		# "rotate" X[]
	push(@VS,shift(@VS));		# "rotate" X[]
}

sub body_00_15 () {
	(
	'($a,$b,$c,$d,$e,$f,$g,$h)=@V;'.
	'&add	($h,$h,$t1)',			# h+=X[i]+K[i]
	'&eor	($t1,$f,$g)',
	'&eor	($t0,$e,$e,"ror#".($Sigma1[1]-$Sigma1[0]))',
	'&add	($a,$a,$t2)',			# h+=Maj(a,b,c) from the past
	'&and	($t1,$t1,$e)',
	'&eor	($t2,$t0,$e,"ror#".($Sigma1[2]-$Sigma1[0]))',	# Sigma1(e)
	'&eor	($t0,$a,$a,"ror#".($Sigma0[1]-$Sigma0[0]))',
	'&ror	($t2,$t2,"#$Sigma1[0]")',
	'&eor	($t1,$t1,$g)',			# Ch(e,f,g)
	'&add	($h,$h,$t2)',			# h+=Sigma1(e)
	'&eor	($t2,$a,$b)',			# a^b, b^c in next round
	'&eor	($t0,$t0,$a,"ror#".($Sigma0[2]-$Sigma0[0]))',	# Sigma0(a)
	'&add	($h,$h,$t1)',			# h+=Ch(e,f,g)
	'&ldr	($t1,sprintf "[sp,#%d]",4*(($j+1)&15))	if (($j&15)!=15);'.
	'&ldr	($t1,"[$Ktbl]")				if ($j==15);'.
	'&ldr	($xt1,"[sp,#64]")			if ($j==31)',
	'&and	($t3,$t3,$t2)',			# (b^c)&=(a^b)
	'&ror	($t0,$t0,"#$Sigma0[0]")',
	'&add	($d,$d,$h)',			# d+=h
	'&add	($h,$h,$t0);'.			# h+=Sigma0(a)
	'&eor	($t3,$t3,$b)',			# Maj(a,b,c)
	'$j++;	unshift(@V,pop(@V)); ($t2,$t3)=($t3,$t2);'
	)
}

$code.=<<___;

.text
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
.word	0				// terminator

.global	sha256_block_data_order_neon
.type	sha256_block_data_order_neon,%function
.align	4
sha256_block_data_order_neon:
.LNEON:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	sub	sp,sp,#16*4+32
	adr	$Ktbl,K256
	bic	x15,x15,#15		// align for 128-bit stores
	add	$len,$inp,$len,lsl#6	// len to point at the end of inp

	ld1		{@VB[0]},[$inp], #16
	ld1		{@VB[1]},[$inp], #16
	ld1		{@VB[2]},[$inp], #16
	ld1		{@VB[3]},[$inp], #16
	ld1		{$TS0},[$Ktbl], #16
	ld1		{$TS1},[$Ktbl], #16
	ld1		{$TS2},[$Ktbl], #16
	ld1		{$TS3},[$Ktbl], #16
	rev32		@VB[0],@VB[0]		// yes, even on
	str		$ctx,[sp,#64]
	rev32		@VB[1],@VB[1]		// big-endian
	str		$inp,[sp,#72]
	mov		$Xfer,sp
	rev32		@VB[2],@VB[2]
	str		$len,[sp,#80]
	rev32		@VB[3],@VB[3]
	add		$TS0,$TS0,@VS[0]
	add		$TS1,$TS1,@VS[1]
	st1		{$TS0},[$Xfer], #16
	add		$TS2,$TS2,@VS[2]
	st1		{$TS1},[$Xfer], #16
	add		$TS3,$TS3,@VS[3]
	st1		{$TS2-$TS3},[$Xfer], #32

	ldp		$A, $B, [$ctx]
	ldp		$C, $D, [$ctx, #8]
	ldp		$E, $F, [$ctx, #16]
	ldp		$G, $H, [$ctx, #24]
	sub		$Xfer,$Xfer,#64
	ldr		$t1,[sp,#0]
	mov		$xt2,xzr
	eor		$t3,$B,$C
	b		.L_00_48

.align	4
.L_00_48:
___
	&Xupdate(\&body_00_15);
	&Xupdate(\&body_00_15);
	&Xupdate(\&body_00_15);
	&Xupdate(\&body_00_15);
$code.=<<___;
	cmp	$t1,#0				// check for K256 terminator
	ldr	$t1,[sp,#0]
	sub	$Xfer,$Xfer,#64
	bne	.L_00_48

	ldr		$inp,[sp,#72]
	ldr		$xt0,[sp,#80]
	sub		$Ktbl,$Ktbl,#256	// rewind $Ktbl
	cmp		$inp,$xt0
	mov		$xt0, #64
	csel		$xt0, $xt0, xzr, eq
	sub		$inp,$inp,$xt0		// avoid SEGV
	ld1		{@VS[0]},[$inp], #16	// load next input block
	ld1		{@VS[1]},[$inp], #16
	ld1		{@VS[2]},[$inp], #16
	ld1		{@VS[3]},[$inp], #16
	str		$inp,[sp,#72]
	mov		$Xfer,sp
___
	&Xpreload(\&body_00_15);
	&Xpreload(\&body_00_15);
	&Xpreload(\&body_00_15);
	&Xpreload(\&body_00_15);
$code.=<<___;
	ldr	$t0,[$xt1,#0]
	add	$A,$A,$t2			// h+=Maj(a,b,c) from the past
	ldr	$t2,[$xt1,#4]
	ldr	$t3,[$xt1,#8]
	ldr	$t4,[$xt1,#12]
	add	$A,$A,$t0			// accumulate
	ldr	$t0,[$xt1,#16]
	add	$B,$B,$t2
	ldr	$t2,[$xt1,#20]
	add	$C,$C,$t3
	ldr	$t3,[$xt1,#24]
	add	$D,$D,$t4
	ldr	$t4,[$xt1,#28]
	add	$E,$E,$t0
	str	$A,[$xt1],#4
	add	$F,$F,$t2
	str	$B,[$xt1],#4
	add	$G,$G,$t3
	str	$C,[$xt1],#4
	add	$H,$H,$t4
	str	$D,[$xt1],#4

	stp	$E, $F, [$xt1]
	stp	$G, $H, [$xt1, #8]

	b.eq	0f
	mov	$Xfer,sp
	ldr	$t1,[sp,#0]
	eor	$t2,$t2,$t2
	eor	$t3,$B,$C
	b	.L_00_48

0:	add	sp,sp,#16*4+32
	ldp	x29, x30, [sp], #16
	ret

.size	sha256_block_data_order_neon,.-sha256_block_data_order_neon
___
}}}

foreach (split($/,$code)) {

	s/\`([^\`]*)\`/eval $1/geo;

	print $_,"\n";
}

close STDOUT; # enforce flush

