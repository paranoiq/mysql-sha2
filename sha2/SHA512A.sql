DELIMITER ;;

/**
 * SHA-512 and SHA-384 hashing algorythm
 * 
 * @author Vlasta Neubauer [paranoiq@centrum.cz]
 */
CREATE FUNCTION `SHA512A`(`msg` mediumblob, `sha384` tinyint) RETURNS varchar(128) CHARSET utf8
    NO SQL
    DETERMINISTIC
    COMMENT 'SHA-512 and SHA-384 hashing algorythm'
BEGIN
    DECLARE k, w BLOB;
    DECLARE ppmsg, chunk MEDIUMBLOB;
    DECLARE a, b, c, d, e, f, g, h, 
            h0, h1, h2, h3, h4, h5, h6, h7, 
            wn, ssig0, ssig1, bsig0, bsig1, maj, ch, t1, t2, i,
            msglen, npaddingbits, len, ppmsglen, numchunks, currentchunk BIGINT UNSIGNED;
    
    -- 80 SHA512 constants K0 - K79
    SET k = UNHEX(
        '428A2F98D728AE227137449123EF65CDB5C0FBCFEC4D3B2FE9B5DBA58189DBBC'
        '3956C25BF348B53859F111F1B605D019923F82A4AF194F9BAB1C5ED5DA6D8118'
        'D807AA98A303024212835B0145706FBE243185BE4EE4B28C550C7DC3D5FFB4E2'
        '72BE5D74F27B896F80DEB1FE3B1696B19BDC06A725C71235C19BF174CF692694'
        'E49B69C19EF14AD2EFBE4786384F25E30FC19DC68B8CD5B5240CA1CC77AC9C65'
        '2DE92C6F592B02754A7484AA6EA6E4835CB0A9DCBD41FBD476F988DA831153B5'
        '983E5152EE66DFABA831C66D2DB43210B00327C898FB213FBF597FC7BEEF0EE4'
        'C6E00BF33DA88FC2D5A79147930AA72506CA6351E003826F142929670A0E6E70'
        '27B70A8546D22FFC2E1B21385C26C9264D2C6DFC5AC42AED53380D139D95B3DF'
        '650A73548BAF63DE766A0ABB3C77B2A881C2C92E47EDAEE692722C851482353B'
        'A2BFE8A14CF10364A81A664BBC423001C24B8B70D0F89791C76C51A30654BE30'
        'D192E819D6EF5218D69906245565A910F40E35855771202A106AA07032BBD1B8'
        '19A4C116B8D2D0C81E376C085141AB532748774CDF8EEB9934B0BCB5E19B48A8'
        '391C0CB3C5C95A634ED8AA4AE3418ACB5B9CCA4F7763E373682E6FF3D6B2B8A3'
        '748F82EE5DEFB2FC78A5636F43172F6084C87814A1F0AB728CC702081A6439EC'
        '90BEFFFA23631E28A4506CEBDE82BDE9BEF9A3F7B2C67915C67178F2E372532B'
        'CA273ECEEA26619CD186B8C721C0C207EADA7DD6CDE0EB1EF57D4F7FEE6ED178'
        '06F067AA72176FBA0A637DC5A2C898A6113F9804BEF90DAE1B710B35131C471B'
        '28DB77F523047D8432CAAB7B40C724933C9EBE0A15C9BEBC431D67C49C100D4C'
        '4CC5D4BECB3E42B6597F299CFC657E2A5FCB6FAB3AD6FAEC6C44198C4A475817');
    
    
    IF sha384 THEN
        -- hash initialization SHA-384
        SET h0 = 0xCBBB9D5DC1059ED8, h1 = 0x629A292A367CD507, h2 = 0x9159015A3070DD17, h3 = 0x152FECD8F70E5939, 
            h4 = 0x67332667FFC00B31, h5 = 0x8EB44A8768581511, h6 = 0xDB0C2E0D64F98FA7, h7 = 0x47B5481DBEFA4FA4;
    ELSE
        -- hash initialization SHA-512
        SET h0 = 0x6A09E667F3BCC908, h1 = 0xBB67AE8584CAA73B, h2 = 0x3C6EF372FE94F82B, h3 = 0xA54FF53A5F1D36F1, 
            h4 = 0x510E527FADE682D1, h5 = 0x9B05688C2B3E6C1F, h6 = 0x1F83D9ABFB41BD6B, h7 = 0x5BE0CD19137E2179;
    END IF;
    
    SET msglen = LENGTH(msg) * 8;
    SET npaddingbits = 8;
    
    WHILE ((msglen + npaddingbits) % 1024) != 896 DO
        SET npaddingbits = npaddingbits + 8;
    END WHILE;
    
    SET ppmsg = CONCAT(msg, CHAR(0x80), REPEAT(CHAR(0x00), (npaddingbits - 8) / 8), UNHEX(LPAD(HEX(msglen), 32, '0')));
    SET ppmsglen = LENGTH(ppmsg) * 8;
    SET numchunks = ppmsglen >> 10; -- 2^10 bit chunk size
    
    SET currentchunk = 1;
    REPEAT
        SET chunk = SUBSTR(ppmsg, ((currentchunk - 1) * 128) + 1, 128);
        SET a = h0, b = h1, c = h2, d = h3, 
            e = h4, f = h5, g = h6, h = h7;
        
        SET i = 0;
        SET w = chunk;
        WHILE i < 80 DO
            IF i < 16 THEN
                SET wn = ARRAY_GET_BIGINT(w, i);
            ELSE    
                SET wn = ARRAY_GET_BIGINT(w, i - 15);
                SET ssig0 = ROR_BIGINT(wn,  1) ^ ROR_BIGINT(wn,  8) ^ (wn >>  7);
                
                SET wn = ARRAY_GET_BIGINT(w, i -  2);
                SET ssig1 = ROR_BIGINT(wn, 19) ^ ROR_BIGINT(wn, 61) ^ (wn >>  6);
                
                SET wn = ARRAY_GET_BIGINT(w, i - 16) + ssig0 + ARRAY_GET_BIGINT(w, i - 7) + ssig1;
                
                SET w  = CONCAT(w, CHAR(wn >> 56, (wn & 0xFF000000000000) >> 48, (wn & 0xFF0000000000) >> 40, 
                    (wn & 0xFF00000000) >> 32, (wn & 0xFF000000) >> 24, (wn & 0xFF0000) >> 16, (wn & 0xFF00) >> 8, wn & 0xFF));
            END IF;
            
            SET bsig0 = ROR_BIGINT(a, 28) ^ ROR_BIGINT(a, 34) ^ ROR_BIGINT(a, 39);
            SET bsig1 = ROR_BIGINT(e, 14) ^ ROR_BIGINT(e, 18) ^ ROR_BIGINT(e, 41);
            
            SET ch = (e & f) ^ ((~e) & g);
            SET maj = (a & b) ^ (a & c) ^ (b & c);
            
            SET t1 = h + bsig1 + ch + ARRAY_GET_BIGINT(k, i) + wn;
            SET t2 = bsig0 + maj;
            
            SET h = g;
            SET g = f;
            SET f = e;
            SET e = d + t1;
            SET d = c;
            SET c = b;
            SET b = a;
            SET a = t1 + t2;
            
            SET i = i + 1;
        END WHILE;
        
        SET h0 = h0 + a, h1 = h1 + b, h2 = h2 + c, h3 = h3 + d, 
            h4 = h4 + e, h5 = h5 + f, h6 = h6 + g, h7 = h7 + h;
        SET currentchunk = currentchunk + 1;
    UNTIL currentchunk > numchunks
    END REPEAT;
    
    IF sha384 THEN
        RETURN LOWER(CONCAT(
            LPAD(HEX(h0), 16, '0'), LPAD(HEX(h1), 16, '0'), LPAD(HEX(h2), 16, '0'), LPAD(HEX(h3), 16, '0'), 
            LPAD(HEX(h4), 16, '0'), LPAD(HEX(h5), 16, '0')));
    ELSE 
        RETURN LOWER(CONCAT(
            LPAD(HEX(h0), 16, '0'), LPAD(HEX(h1), 16, '0'), LPAD(HEX(h2), 16, '0'), LPAD(HEX(h3), 16, '0'), 
            LPAD(HEX(h4), 16, '0'), LPAD(HEX(h5), 16, '0'), LPAD(HEX(h6), 16, '0'), LPAD(HEX(h7), 16, '0')));
    END IF;
END;;


CREATE FUNCTION `ARRAY_GET_BIGINT`(`array` blob, `idx` int unsigned) RETURNS bigint(1) unsigned
    NO SQL
    DETERMINISTIC
    COMMENT 'Returns an UNSIGNED BIGINT from BLOB array'
BEGIN
    SET idx = (idx * 8) + 1;
    RETURN (ORD(SUBSTR(array, idx + 0, 1)) << 56)
         | (ORD(SUBSTR(array, idx + 1, 1)) << 48)
         | (ORD(SUBSTR(array, idx + 2, 1)) << 40)
         | (ORD(SUBSTR(array, idx + 3, 1)) << 32)
         | (ORD(SUBSTR(array, idx + 4, 1)) << 24) 
         | (ORD(SUBSTR(array, idx + 5, 1)) << 16) 
         | (ORD(SUBSTR(array, idx + 6, 1)) <<  8) 
         | (ORD(SUBSTR(array, idx + 7, 1)));
END;;


CREATE FUNCTION `ROR_BIGINT`(`inp` bigint, `shft` tinyint) RETURNS bigint(1) unsigned
    NO SQL
    DETERMINISTIC
    COMMENT 'Right bit rotation on 64-bit integer'
BEGIN
    RETURN ((inp >> shft) | (inp << (64 - shft)));
END;;

