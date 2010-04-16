/**
 * SHA-256 and SHA-224 hashing algorythms
 * 
 * @author Gwynne Raskind (http://blog.darkrainfall.org/)
 * @author Vlasta Neubauer [paranoiq@paranoiq.cz]
 */
CREATE FUNCTION `SHA256A`(`msg` mediumblob, `sha224` tinyint) RETURNS varchar(64) CHARSET utf8
    NO SQL
    DETERMINISTIC
    COMMENT 'SHA-256 and SHA-224 hashing algorythm'
BEGIN
    DECLARE k, w BLOB;
    DECLARE ppmsg, chunk MEDIUMBLOB;
    DECLARE a, b, c, d, e, f, g, h, 
            h0, h1, h2, h3, h4, h5, h6, h7, 
            wn, s0, s1, maj, ch, t1, t2, i,
            msglen, npaddingbits, len, ppmsglen, numchunks, currentchunk INT UNSIGNED;
    
    DECLARE modvalue BIGINT UNSIGNED DEFAULT 0x00000000FFFFFFFF;
    
    -- 64 SHA-256 constants K0 - K63
    SET k = UNHEX(
        '428A2F9871374491B5C0FBCFE9B5DBA53956C25B59F111F1923F82A4AB1C5ED5'
        'D807AA9812835B01243185BE550C7DC372BE5D7480DEB1FE9BDC06A7C19BF174'
        'E49B69C1EFBE47860FC19DC6240CA1CC2DE92C6F4A7484AA5CB0A9DC76F988DA'
        '983E5152A831C66DB00327C8BF597FC7C6E00BF3D5A7914706CA635114292967'
        '27B70A852E1B21384D2C6DFC53380D13650A7354766A0ABB81C2C92E92722C85'
        'A2BFE8A1A81A664BC24B8B70C76C51A3D192E819D6990624F40E3585106AA070'
        '19A4C1161E376C082748774C34B0BCB5391C0CB34ED8AA4A5B9CCA4F682E6FF3'
        '748F82EE78A5636F84C878148CC7020890BEFFFAA4506CEBBEF9A3F7C67178F2');
    
    IF sha224 THEN
        -- SHA-224 hash initialization
        SET h0 = 0xC1059ED8, h1 = 0x367CD507, h2 = 0x3070DD17, h3 = 0xF70E5939, 
            h4 = 0xFFC00B31, h5 = 0x68581511, h6 = 0x64F98FA7, h7 = 0xBEFA4FA4;
    ELSE
        -- SHA-256 hash initialization
        SET h0 = 0x6A09E667, h1 = 0xBB67AE85, h2 = 0x3C6EF372, h3 = 0xA54FF53A, 
            h4 = 0x510E527F, h5 = 0x9B05688C, h6 = 0x1F83D9AB, h7 = 0x5BE0CD19;
    END IF;
    
    SET msglen = LENGTH(msg) * 8, npaddingbits = 8;
    WHILE ((msglen + npaddingbits) % 512) != 448 DO
        SET npaddingbits = npaddingbits + 8;
    END WHILE;
    
    SET ppmsg = CONCAT(msg, CHAR(0x80), REPEAT(CHAR(0x00), (npaddingbits - 8) / 8), UNHEX(LPAD(HEX(msglen), 16, '0')));
    SET ppmsglen = LENGTH(ppmsg) * 8;
    SET numchunks = ppmsglen >> 9, currentchunk = 1;

    REPEAT
        SET chunk = SUBSTRING(ppmsg FROM ((currentchunk - 1) * 64) + 1 FOR 64);
        SET a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7, i = 0;

        SET w = chunk;
        WHILE i < 64 DO
            IF i > 15 THEN
                SET wn = ARRAY_GET_INT(w, i - 15), s0 = ROR_INT(wn,  7) ^ ROR_INT(wn, 18) ^ (wn >>  3),
                    wn = ARRAY_GET_INT(w, i -  2), s1 = ROR_INT(wn, 17) ^ ROR_INT(wn, 19) ^ (wn >> 10),
                    wn = (ARRAY_GET_INT(w, i - 16) + s0 + ARRAY_GET_INT(w, i - 7) + s1) & modvalue,
                    w = CONCAT(w, CHAR(wn >> 24, (wn & 0x00FF0000) >> 16, (wn & 0x0000FF00) >> 8, wn & 0x000000FF));
            ELSE
                SET wn = ARRAY_GET_INT(w, i);
            END IF;

            SET s0 = ROR_INT(a, 2) ^ ROR_INT(a, 13) ^ ROR_INT(a, 22), maj = (a & b) ^ (a & c) ^ (b & c),
                t2 = (s0 + maj) & modvalue,
                s1 = ROR_INT(e, 6) ^ ROR_INT(e, 11) ^ ROR_INT(e, 25), ch = (e & f) ^ ((~e) & g),
                t1 = (h + s1 + ch + ARRAY_GET_INT(k, i) + wn) & modvalue,
                h = g, g = f, f = e, e = (d + t1) & modvalue, d = c, c = b, b = a,
                a = (t1 + t2) & modvalue,
                i = i + 1;
        END WHILE;
        
        SET h0 = (h0 + a) & modvalue, 
            h1 = (h1 + b) & modvalue, 
            h2 = (h2 + c) & modvalue,
            h3 = (h3 + d) & modvalue, 
            h4 = (h4 + e) & modvalue, 
            h5 = (h5 + f) & modvalue,
            h6 = (h6 + g) & modvalue, 
            h7 = (h7 + h) & modvalue,
            currentchunk = currentchunk + 1;
    UNTIL currentchunk > numchunks
    END REPEAT;
    
    IF sha224 THEN
        RETURN LOWER(CONCAT(
            LPAD(HEX(h0), 8, '0'), LPAD(HEX(h1), 8, '0'), LPAD(HEX(h2), 8, '0'), LPAD(HEX(h3), 8, '0'), 
            LPAD(HEX(h4), 8, '0'), LPAD(HEX(h5), 8, '0'), LPAD(HEX(h6), 8, '0')));
    ELSE
        RETURN LOWER(CONCAT(
            LPAD(HEX(h0), 8, '0'), LPAD(HEX(h1), 8, '0'), LPAD(HEX(h2), 8, '0'), LPAD(HEX(h3), 8, '0'), 
            LPAD(HEX(h4), 8, '0'), LPAD(HEX(h5), 8, '0'), LPAD(HEX(h6), 8, '0'), LPAD(HEX(h7), 8, '0')));
    END IF;
END


CREATE FUNCTION `ARRAY_GET_INT`(`array` blob, `idx` int unsigned) RETURNS int(1) unsigned
    NO SQL
    DETERMINISTIC
    COMMENT 'Returns an UNSIGNED INT from BLOB array'
BEGIN
    SET idx = (idx * 4) + 1;
    RETURN (ORD(SUBSTR(array, idx + 0, 1)) << 24) 
         | (ORD(SUBSTR(array, idx + 1, 1)) << 16) 
         | (ORD(SUBSTR(array, idx + 2, 1)) <<  8) 
         | (ORD(SUBSTR(array, idx + 3, 1)));
END


CREATE FUNCTION `ROR_INT`(`inp` bigint, `shft` tinyint) RETURNS int(1) unsigned
    NO SQL
    DETERMINISTIC
    COMMENT 'Right bit rotation on 32-bit integer'
BEGIN
    RETURN ((inp >> shft) | (inp << (32 - shft))) & 0x00000000FFFFFFFF;
END

