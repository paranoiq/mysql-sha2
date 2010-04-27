DELIMITER ;;

/**
 * SHA2 algorythms wrapper
 * 
 * @author Vlasta Neubauer [paranoiq@paranoiq.cz]
 */
CREATE FUNCTION `SHA2`(`alg` smallint, `msg` mediumblob) RETURNS varchar(128) CHARSET utf8
    NO SQL
    DETERMINISTIC
    COMMENT 'SHA2 hashing functions wrapper'
BEGIN
    CASE alg
        WHEN 224 THEN RETURN SHA256A(msg, 1);
        WHEN 256 THEN RETURN SHA256A(msg, 0);
        WHEN 384 THEN RETURN SHA512A(msg, 1);
        WHEN 512 THEN RETURN SHA512A(msg, 0);
        ELSE RETURN ERROR.WRONG_ALGORYTHM_IDENTIFICATOR_USED();
    END CASE;
END;;
