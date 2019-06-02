<p align="center">
  <img width="300" height="460" src="logo.jpg">
</p>
# balloon hash

This is a [balloon hash](https://crypto.stanford.edu/balloon/) implementation. It is taylored for organism's needs.
The [paper](https://eprint.iacr.org/2016/027.pdf) can be read for more information about the memory hardness properties.

Balloon is provably sequentially sound and is a better alternative to pbkdf2. 
It is used as a key derivation function and in places where at a cost to performance one desires memory hardness properties 
as a defense mechanism. 