

typedef string kdc_name<>;
typedef opaque spn_key_buf<>;

enum spn_key_type {
  DES_CBC_CRC,
  DES_CBC_MD4,
  DES_CBC_MD5,
  DES3_CBC_MD5,
  DES3_CBC_SHA1_KD,
  AES128_CTS_HMAC_SHA1_96,
  AES256_CTS_HMAC_SHA1_96,
  RC4_HMAC,
  RC4_HMAC_EXP,
  RC4_HMAC_OLD_EXP
};

struct spn_key {
  spn_key_type type;
  spn_key_buf value;
};
typedef spn_key spn_key_list<>;

struct spn {
  kdc_name name;
  spn_key_list keys;  
};
typedef spn spn_list<>;

program KDC_PROG {
  version KDC_V1 {
    void KDC_NULL( void ) = 0;
    spn KDC_FIND( kdc_name ) = 1;
    void KDC_ADD( spn ) = 2;
    void KDC_REMOVE( kdc_name ) = 3;
  } = 1;
} = 901980025;


