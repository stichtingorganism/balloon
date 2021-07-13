# balloon hash

This is a [balloon hash](https://crypto.stanford.edu/balloon/) implementation. It is taylored for organism's needs.
The [paper](https://eprint.iacr.org/2016/027.pdf) can be read for more information about the memory hardness properties.

Balloon is provably sequentially sound and is a better alternative to pbkdf2. 
It is used as a key derivation function and in places where at a cost to performance one desires memory hardness properties 
as a defense mechanism. 




/*
 - https://eprint.iacr.org/2016/027.pdf
 - https://crypto.stanford.edu/balloon/
 - https://github.com/codahale/balloonhash/blob/master/src/main/java/com/codahale/balloonhash/BalloonHash.java
 - https://github.com/moxnetwork/mox/blob/master/attic/balloon.go
 - https://github.com/nachonavarro/balloon-hashing

    The algorithm consists of three main parts, as explained in the paper.
    The first step is the expansion, in which the system fills up a buffer
    with pseudorandom bytes derived from the password and salt by computing
    repeatedly the hash function on a combination of the password and the previous hash.
    The second step is mixing, in which the system mixes time_cost number of times the
    pseudorandom bytes in the buffer. At each step in the for loop, it updates the nth block
    to be the hash of the n-1th block, the nth block, and delta other blocks chosen at random
    from the buffer. In the last step, the extraction, the system outputs as the hash the last element in the buffer.


    High-security key derivation 128 MB space from ref implementation.

    The larger the time parameter, the longer the hash computation will take.
    The choice of time has an effect on the memory-hardness properties of the scheme: the larger time is,
    the longer it takes to compute the function in small space.
*/