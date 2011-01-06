Implementation of SHA2 hashing functions and related HMAC functions in PL/MySQL


Author: Vlasta Neubauer [paranoiq@centrum.cz]


License and warranty:
---------------------
This software is not licensed. Consider it as public domain. Use it as you like.
The author is not responsible for any damage caused by using this software.


Warning:
--------
These SHA2 functions in pure PL/MySQL are very slow. Using them in a time 
critical job or using them to process large amount of data is not advised.


Example usage:
--------------
SELECT SHA2(512, 'message to hash');
SELECT HMAC_SHA2(512, 'message to sign', 'key');

First atribute of SHA2 and HMAC_SHA2 functions is the algorythm bit length.
Valid values are integers: 224, 256, 384 and 512


Content:
--------
SHA2.sql:
    - wrapper function for hashing SHA2(algorythm, message)
HMAC_SHA2.sql:
    - message authentication function HMAC_SHA2(algorythm, message, key)
    - helper function STRING_XOR
SHA256A.sql:
    - function SHA256A implementing SHA-256 and SHA-224 algorythms
    - helper functions ARRAY_GET_INT and ROR_INT
SHA512A.sql:
    - function SHA512A implementing SHA-512 and SHA-384 algorythms
    - helper functions ARRAY_GET_BIGINT and ROR_BIGINT
SHA256A.test.sql:
SHA512A.test.sql:
HMAC_SHA2.test.sql:
    - testing vectors. simply run this as SQL code. all queries should return 1

Enjoy!
