# libecdsautil

This will contain safe wrappers for `libecdsautil-sys`, yet currently only provides a representation of fastd public keys based on curve25519-dalek, as well as dalek-ff-group.



## theory

__private fastd:__
282615cc09656f1f3dbe5fa24b640bfd48d8302f982477d38335c2ffab84c17e

__derived public fastd:__
faebc966b4b255d9383f44fb2abc1b8b4d596ced9951a421af4df97f62aa1a7b

Public fastd keys (u8[32]~256bit) represent a point on the legacy curve.
Points on Edwards25519 (as used in Ed25519) should share the same y-coordinate;
the x-coordinate can be calculated using a multiplication as in `ecc_25519_store_xy_legacy` and `ecc_25519_load_xy_legacy`.

In Ed25519 public keys are stored in "Edwards y"-format, meaning the first 255 bits represent the y coordinate, while the high byte of the last byte gives the sign of x.

In libuecc public keys are stored in what could be called CompressedEdwardsX, as the x coordinate is packed alongside the least significant bit (lsb) of the y-coordinate.

Decompressed points are represented as a four tuple {X,Y,Z,T} with:

$x= {X \over Z}$

$y={Y \over Z}$

$ x\*y={T \over Z} $

Each of the tuples segments is u32[32]~1024bit

**->** But the last 24 are actually zeroes, while it's not within a calculation

__Steps to verify:__
- [x] use libuecc to decompress a fastd public key
- [x] load decompressed key as `EdwardsPoint` using rusts `curve25519_dalek`-crate
- [x] implement `compressX` for `EdwardsPoint` which should emit the fastd public key again
- [x] implement `decompress` for `CompressedEdwardsX` as opposing to he former
- [x] then fastd keys could be loaded as `CompressedEdwardsX` and converted to Daleks representation
  and later fed into the verify-functions of libecdsautil

**Left to do for compressed_points.rs**

- [x] implement `EDWARDS_D`
- [x] implement sqrt_ratio_i()
- [x] implement `is_negative` / `is_odd`
- [x] implement `conditional_negate`
- [ ] upstream `EDWARDS_D`
- [ ] upstream sqrt_ratio_i()
- [ ] upstream `is_negative` / `is_odd`
- [ ] upstream `conditional_negate`
