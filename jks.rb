=begin
JKS/JCEKS file format decoder.
Direct port of https://github.com/doublereedkurt/pyjks/blob/master/jks/jks.py
This is MIT licensed, since the source file is MIT licensed.

Use in conjunction with OpenSSL to translate to PEM, or load private key and certs
directly into openssl structs and wrap sockets.

See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b14/sun/security/provider/JavaKeyStore.java#JavaKeyStore.engineLoad%28java.io.InputStream%2Cchar%5B%5D%29
See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/JceKeyStore.java#JceKeyStore
=end
require 'openssl'
require 'pp'
require 'digest'
require 'base64'

#Globals
Cert = Struct.new('Cert', :alias, :timestamp, :type, :cert)
PrivateKey = Struct.new('PrivateKey', :alias, :timestamp, :pkey, :cert_chain)

#b8 = struct.Struct('>Q')
#b4 = struct.Struct('>L')
#b2 = struct.Struct('>H')

MAGIC_NUMBER_JKS = 0xFEEDFEED
MAGIC_NUMBER_JCEKS = 0xCECECECE
VERSION = 2
SIGNATURE_WHITENING = 'Mighty Aphrodite'
SUN_JKS_ALGO_ID = ['1','3','6','1','4','1','42','2','17','1','1'] # JavaSoft proprietary key-protection algorithm
SUN_JCE_ALGO_ID = ['1','3','6','1','4','1','42','2','19','1']   # PBE_WITH_MD5_AND_DES3_CBC_OID

class KeyStore
    attr_accessor :private_keys
    attr_accessor :certs
    def initialize(m_private_keys, m_certs)
        @private_keys = m_private_keys
        @certs = m_certs
    end

    def self.load(filename, password)
      return KeyStore::loads(File.binread(filename), password)
    end

    def self.loads(data, password)
        magic_number = get32(data, 0)
        if magic_number == MAGIC_NUMBER_JKS
          filetype = 'jks'
        elsif magic_number == MAGIC_NUMBER_JCEKS
            filetype = 'jceks'
        else
            raise ArgumentError, 'Not a JKS or JCEKS keystore (magic number wrong; expected FEEDFEED resp. CECECECE)'
        end

        version = get32(data, 4)
        raise ArgumentError, "Unsupported keystore version; only v2 supported, found v#{version}" if version != 2

        entry_count = get32(data, 8)
        pos = 12
        private_keys = []
        certs = []

        (0..entry_count-1).each do
            tag = get32(data, pos)
            pos += 4
            aliass, pos = _read_utf(data, pos)
            timestamp = get64(data, pos) # milliseconds since UNIX epoch
            pos += 8

            if tag == 1  # private key
                ber_data, pos = _read_data(data, pos)
                chain_len = get32(data, pos)
                pos += 4

                cert_chain = []
                (0...chain_len).each do
                    cert_type, pos = _read_utf(data, pos)
                    cert_data, pos = _read_data(data, pos)
                    cert_chain << ([cert_type, cert_data])
                end #inner for

                # at this point, ber_data is a PKCS#8 EncryptedPrivateKeyInfo
                asn1_data = OpenSSL::ASN1.decode(ber_data)
                algo_id = asn1_data.value[0].value[0].value.split(".")
                encrypted_private_key = asn1_data.value[1].value
                plaintext = ''
                if filetype == 'jks'
                    if algo_id != SUN_JKS_ALGO_ID
                        raise ArgumentError, "Unknown JKS private key algorithm OID: #{algo_id}"
                    end
                    plaintext = _sun_jks_pkey_decrypt(encrypted_private_key, password)

                elsif filetype == 'jceks'
                    if algo_id == SUN_JKS_ALGO_ID
                        plaintext = _sun_jks_pkey_decrypt(encrypted_private_key, password)
                    elsif algo_id == SUN_JCE_ALGO_ID
                        #UNTESTED - I don't have any JCEKS keystores to test on
                        salt = asn1_data.value[0].value[1].value[0].value # see section A.3: PBES1 and definitions of AlgorithmIdentifier and PBEParameter in RFC 2898
                        iteration_count = asn1_data.value[0].value[1].value[1].value.to_i
                        plaintext = _sun_jce_pkey_decrypt(encrypted_private_key, password, salt, iteration_count)
                    else
                        raise ArgumentError, "Unknown JCEKS private key algorithm OID: #{algo_id}"
                    end #algo_id ==
                end #filetype ==
                berkey = OpenSSL::ASN1.decode(plaintext)
                key = berkey.value[2].value
                private_keys << PrivateKey.new(aliass, timestamp, key, cert_chain)

            elsif tag == 2  # cert
                cert_type, pos = _read_utf(data, pos)
                cert_data, pos = _read_data(data, pos)
                certs << Cert.new(aliass, timestamp, cert_type, cert_data)

            elsif tag == 3
                if filetype != 'jceks'
                  raise ArgumentError, 'Unexpected entry tag {0} encountered in JKS keystore; only supported in JCEKS keystores'.format(tag)
                end
            end #tag ==
        end #outer for

        # the keystore integrity check uses the UTF-16BE encoding of the password
        password_utf16 = password.encode('utf-16be')
        passdig = (password_utf16.bytes.to_a.pack('C*').force_encoding('utf-8')) + SIGNATURE_WHITENING + data[0...pos]
        if Digest::SHA1.new.digest(passdig) != data[pos..-1]
            raise ValueError('Hash mismatch; incorrect password or data corrupted')
        end

        return KeyStore.new(private_keys, certs)
    end
end

def get8(data, pos)
  data[pos].unpack('C>')[0]
end

def get16(data, pos)
  data[pos..pos+2].unpack('S>')[0]
end

def get32(data, pos)
  data[pos..pos+4].unpack('L>')[0]
end

def get64(data, pos)
  data[pos..pos+8].unpack('Q>')[0]
end


def _read_utf(data, pos)
    size = get16(data, pos)
    pos += 2
    return data[pos...pos+size].encode('utf-8'), pos+size
end


def _read_data(data, pos)
    size = get32(data, pos)
    pos += 4
    return data[pos...pos+size], pos+size
end


def _sun_jks_pkey_decrypt(data, password)
    #implements private key crypto algorithm used by JKS files
    bld = ''
    # the JKS algorithm uses a regular Java UTF16-BE string for the password, so insert 0 bytes
    password.split('').each do |c|
      bld << 0x00
      bld << c.encode('ISO-8859-1')
    end

    iv, data, check = data[0...20], data[20...-20], data[-20..-1]
    bvb = _jks_keystream(iv, bld)
    xoring = data.bytes.zip(bvb)

    keybld = ''

    xoring.each do |a|
        keybld << (a[0] ^ a[1]).chr
    end

    digested = Digest::SHA1.new.digest(bld + keybld)
    if digested != check
      raise ArgumentError, 'bad hash check on private key'
    end
    keybld
end


def _jks_keystream(iv, password)
    #helper generator for _sun_pkey_decrypt
    cur = iv
    sha1 = Digest::SHA1.new
    Enumerator.new do |enum|
      while true
        cur = sha1.digest(password + cur)
        cur.bytes.each do |byte|
          enum.yield byte
        end
      end
    end
end

def _sun_jce_pkey_decrypt(data, password, salt, iteration_count)
    key, iv = _sun_jce_derive_cipher_key_iv(password, salt, iteration_count)

    des3 = OpenSSL::Cipher.new('des3')
    des3.decrypt
    des3.key = key
    des3.iv = iv
    padded = des3.update(data) + des3.final
    _strip_pkcs5_padding(padded)
end

def _sun_jce_derive_cipher_key_iv(password, salt, iteration_count)
=begin
    PKCS#8-formatted private key with a proprietary password-based encryption algorithm.
    It is based on password-based encryption as defined by the PKCS #5 standard, except that is uses triple DES instead of DES.
    Here's how this algorithm works:
      1. Create random salt and split it in two halves. If the two halves are identical, invert one of them.
      2. Concatenate password with each of the halves.
      3. Digest each concatenation with c iterations, where c is the iterationCount. Concatenate the output from each digest round with the password,
         and use the result as the input to the next digest operation. The digest algorithm is MD5.
      4. After c iterations, use the 2 resulting digests as follows: The 16 bytes of the first digest and the 1st 8 bytes of the 2nd digest
         form the triple DES key, and the last 8 bytes of the 2nd digest form the IV.
    See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/PBECipherCore.java#PBECipherCore.deriveCipherKey%28java.security.Key%29
=end
    # Note: unlike JKS, the JCE algorithm uses an ASCII string for the password, not a regular Java/UTF-16BE string; no need to double up on the password bytes
    if salt.length != 8
        raise ArgumentError, 'Expected 8-byte salt for JCE private key encryption algorithm'
    end
    md5 = Digest::MD5.new
    salt_halves = [salt[0...4], salt[4...8]]
    if salt_halves[0] == salt_halves[1]
        salt_halves[0].reverse! # reversed
    end
    derived = ''
    (0...2).each do |i|
        to_be_hashed = salt_halves[i]
        (0...iteration_count).each do
            to_be_hashed = md5.digest(to_be_hashed + password)
        end
        derived += to_be_hashed
    end
    key = derived[0...-8] # = 24 bytes
    iv = derived[-8..-1]
    return key, iv
end

def _strip_pkcs5_padding(m)
    # drop PKCS5 padding:  8-(||M|| mod 8) octets each with value 8-(||M|| mod 8)
    last_byte = m[-1].ord
    if last_byte <= 0 || last_byte > 8
        raise ArgumentError, 'Unable to strip PKCS5 padding: invalid padding found'
    end
    # the <last_byte> bytes of m must all have value <last_byte>, otherwise something's wrong
    if m[-last_byte..-1] != last_byte.chr * last_byte
        raise ArgumentError, 'Unable to strip PKCS5 padding: invalid padding found'
    end

    m[0...-last_byte]
end

def get_pem(data, type)
  retval = ''
  retval << "-----BEGIN #{type}-----\r\n"
  coded = Base64.strict_encode64(data)
  while coded.length > 0 do
    retval << coded.slice!(0..63)
    retval << "\r\n"
  end
  #wrappedarr.each do |wa|
  #  retval << wa
  #  retval << "\r\n"
  #end
  retval << "-----END #{type}-----"
  retval
end

def test()
  rslt = KeyStore::load("test.jks", 'password')
  rslt.private_keys.each do |pk|
    puts "Private key: #{pk.alias}"
    puts get_pem(pk.pkey, 'RSA PRIVATE KEY')
    pk.cert_chain.each do |cert|
      puts get_pem(cert[1], 'CERTIFICATE')
    end
    puts
  end

  rslt.certs.each do |cert|
    puts "Certificate: #{cert.alias}"
    puts get_pem(cert.cert, 'CERTIFICATE')
    puts
  end
end

test()
