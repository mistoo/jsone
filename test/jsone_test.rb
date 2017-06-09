require 'test_helper'

class JSONeTest < Minitest::Test
  def a_hash
    { a: 1, b: 'foo', d: 'foo', c: { d: 'foo' } }.clone
  end

  def a_json_file(hash = nil)
    hash = a_hash if hash.nil?
    
    path = "#{ENV['JSONE_KEYDIR']}/foo.json"
    FileUtils.rm_f path
    FileUtils.rm_f "#{path}e"
    File.write(path, JSON.pretty_generate(hash))
    path
  end
  
  def test_encryption
    hash = a_hash.freeze

    key = JSONe.gen_key
    enc_hash = JSONe.encrypt(hash, key, add_key: false)

    enc_hash.freeze
    decrypted = JSONe.decrypt(enc_hash, key)

    # puts JSON.pretty_generate(enc_hash)
    # puts JSON.pretty_generate(decrypted)

    assert_equal hash, decrypted
  end

  def test_encryption_with_incl_key
    hash = a_hash

    key = JSONe.gen_key
    JSONe.write_key(key)

    enc_hash = JSONe.encrypt(hash, key, add_key: true)
    assert_equal enc_hash[JSONe::PUBLICKEY_KEY], JSONe.to_hex(key.public_key)
    enc_hash.freeze
    decrypted = JSONe.decrypt(enc_hash)
    decrypted.delete(JSONe::PUBLICKEY_KEY)

    # puts JSON.pretty_generate(enc_hash)
    # puts JSON.pretty_generate(decrypted)

    assert_equal hash, decrypted
  end

  def test_encryption_encrypted
    hash = a_hash

    key = JSONe.gen_key
    enc_hash = JSONe.encrypt(hash, key, add_key: false)

    hash[:new_key] = 'foo'
    enc_hash[:new_key] = 'foo'

    enc_hash2 = JSONe.encrypt(enc_hash, key, add_key: false)
    assert_equal enc_hash2[:b], enc_hash[:b]
    decrypted = JSONe.decrypt(enc_hash2, key)

    # puts JSON.pretty_generate(hash)
    # puts JSON.pretty_generate(enc_hash2)
    # puts JSON.pretty_generate(decrypted)

    assert_equal hash, decrypted
  end

  def test_file_encryption
    # JSONe.print_key(key)
    src_hash = a_hash
    src = a_json_file(a_hash)

    key = JSONe.gen_key

    File.write(src, JSON.pretty_generate(src_hash))
    dest = JSONe.encrypt_file(src, key)
    hash = JSON.parse(File.read(dest))

    assert_equal src_hash[:b] == hash['b'], false
    assert_equal hash['b'].start_with?('__!jsone'), true
  end
  
  def test_file_encryption_merge
    key = JSONe.gen_key
    JSONe.write_key(key)

    src_hash = a_hash
    src = a_json_file(a_hash)
    
    dest = JSONe.encrypt_file(src, key)
    hash = JSON.parse(File.read(dest))
    
    src_hash2 = src_hash.merge("d" => 'foox', "e" => 'foo')
    File.write(src, JSON.pretty_generate(src_hash2))

    dest = JSONe.encrypt_file(src, key)
    hash2 = JSON.parse(File.read(dest))

    assert_equal hash['b'], hash2['b'] # same cipher
    assert_equal hash['d'] == hash2['d'], false # value changed, so cipher do
    assert_equal hash2['e'].nil?, false         # new key
    assert_equal hash[JSONe::PUBLICKEY_KEY], hash2[JSONe::PUBLICKEY_KEY] 

    # key change
    new_key = JSONe.gen_key
    dest = JSONe.encrypt_file(src, new_key)
    hash3 = JSON.parse(File.read(dest))
    
    assert_equal hash2['b'] == hash3['b'], false # new cipher (new key is used)
    assert_equal hash2[JSONe::PUBLICKEY_KEY] != hash3[JSONe::PUBLICKEY_KEY], true # new cipher (new key is used)
  end

  def test_file_encryption_nokey
    key = JSONe.gen_key
    key_path = JSONe.write_key(key)

    src_hash = a_hash
    src = a_json_file(src_hash)
    
    dest = JSONe.encrypt_file(src, key)
    hash = JSON.parse(File.read(dest))

    FileUtils.rm(key_path)
    
    new_key = JSONe.gen_key
    dest = JSONe.encrypt_file(src, new_key)
    hash2 = JSON.parse(File.read(dest))

    #puts JSON.pretty_generate(hash)
    #puts JSON.pretty_generate(hash2)


    assert_equal hash['b'] == hash2['b'], false # new key
    assert_equal hash2[JSONe::PUBLICKEY_KEY], JSONe.to_hex(new_key.public_key)
  end
end
