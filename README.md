# Elgamal-with-ECC
Elgamal encryption with Elliptic Curve Cryptography - Assignment 5

# Compilation 
g++ -std=gnu++11 ecc.cpp -o ecc 

# Execution
./ecc

# Sample Input - Output
1. Elliptic curve : (y^2)mod p = (x^3 + ax + b) mod p
2. Enter values for a, b and p : 0 -4 257
6. Base Point : (2,2)
7. Order : 128
8. Enter the private key for public key generation : 101
10. Public Key : (197,167)
11. Enter an Ephimeral Key : 41
12. Enter msg for encryption x and y values : 112 26
13. Encrypted msg : {(136,128) , (246,174)}
14. Decryption : 
15. Decrypted msg : (112,26)


# Submission Details
Name : Nileena P C 
RollNo : CS21M519 
Email-ID : nileena.pc98@gmail.com
