/**
 * HMAC function based on SHA2 algorythms
 * 
 * @author Vlasta Neubauer [paranoiq@paranoiq.cz]
 */
CREATE FUNCTION `HMAC_SHA2`(`alg` smallint, `msg` mediumblob, `msgkey` mediumblob) RETURNS varchar(128) CHARSET utf8
    NO SQL
    DETERMINISTIC
    COMMENT 'HMAC function based on SHA2 algorythms'
BEGIN
    DECLARE hashlen INT UNSIGNED;
    DECLARE opad, ipad TINYBLOB;
    
    CASE alg
        WHEN 224 THEN SET hashlen = 64;
        WHEN 256 THEN SET hashlen = 64;
        WHEN 384 THEN SET hashlen = 128;
        WHEN 512 THEN SET hashlen = 128;
        ELSE RETURN ERROR.WRONG_ALGORYTHM_IDENTIFICATOR_USED();
    END CASE;
    
    IF LENGTH(msgkey) > hashlen THEN
        SET msgkey = UNHEX(SHA2(msgkey, alg));
    END IF;
    
    SET msgkey = RPAD(msgkey, hashlen, 0x00);
    
    SET ipad = STRING_XOR(msgkey, 0x36);
    SET opad = STRING_XOR(msgkey, 0x5C);
    
    RETURN SHA2( CONCAT(opad, UNHEX( SHA2(CONCAT(ipad, msg), alg) )), alg );
END


/**
 * Returns XOR of binary string and an 8-bit constant
 */
CREATE FUNCTION `STRING_XOR`(`string` mediumblob, `const` tinyint unsigned) RETURNS mediumblob
    NO SQL
    DETERMINISTIC
    COMMENT 'XOR of binary string and 8-bit constant'
BEGIN
    DECLARE len, pos INT UNSIGNED;
    DECLARE result MEDIUMBLOB;
    
    SET len = LENGTH(string);
    SET pos = 1;
    SET result = '';
    
    WHILE pos <= len DO
        SET result = CONCAT( result, LPAD(HEX( ORD(SUBSTR(string, pos, 1)) ^ const ), 2, '0') );
        SET pos = pos + 1;
    END WHILE;
    
    RETURN UNHEX(result);
END

