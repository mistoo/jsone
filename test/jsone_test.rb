require 'test_helper'

class JSONeTest < Minitest::Test
  def test_encryption
    #JSONe.print_key(key)
    
    hash = { a: 1, b: "foo", c: { "d": "foo" } }.freeze

    key = JSONe.gen_key
    enc_hash = JSONe.encrypt(hash, key, add_key: false)
    
    enc_hash.freeze
    decrypted = JSONe.decrypt(enc_hash, key)
    
    #puts JSON.pretty_generate(enc_hash)
    #puts JSON.pretty_generate(decrypted)

    assert_equal hash, decrypted
  end

  def test_encryption_with_incl_key
    #JSONe.print_key(key)
    
    hash = { a: 1, b: "foo", c: { "d": "foo" } }

    
    key = JSONe.gen_key
    JSONe.write_key(key)
    
    enc_hash = JSONe.encrypt(hash, key, add_key: true)
    assert_equal enc_hash[JSONe::PUBLICKEY_KEY], JSONe.to_hex(key.public_key)    
    enc_hash.freeze
    decrypted = JSONe.decrypt(enc_hash)
    decrypted.delete(JSONe::PUBLICKEY_KEY)

    #puts JSON.pretty_generate(enc_hash)
    #puts JSON.pretty_generate(decrypted)
    
    assert_equal hash, decrypted
  end

  def test_encryption_encrypted
    #JSONe.print_key(key)
    
    hash = { a: 1, b: "foo", c: { "d": "foo" } }

    key = JSONe.gen_key
    enc_hash = JSONe.encrypt(hash, key, add_key: false)

    hash[:new_key] = "foo"
    enc_hash[:new_key] = "foo"
    
    enc_hash2 = JSONe.encrypt(enc_hash, key, add_key: false)
    assert_equal enc_hash2[:b], enc_hash[:b]
    decrypted = JSONe.decrypt(enc_hash2, key) 
    
    #puts JSON.pretty_generate(hash)
    #puts JSON.pretty_generate(enc_hash2)
    #puts JSON.pretty_generate(decrypted)

    assert_equal hash, decrypted
  end

  def test_file_encryption
    #JSONe.print_key(key)
    src_hash = { a: 1, b: "foo", d: "foo", c: { "d": "foo" } }
    
    key = JSONe.gen_key
    
    src = "#{ENV['JSONE_KEYDIR']}/foo.json"
    FileUtils.rm_f src
    FileUtils.rm_f "#{src}e"
    
    File.write(src, JSON.pretty_generate(src_hash))
    dest = JSONe.encrypt_file(src, key)
    hash = JSON.parse(File.read(dest))

    assert_equal src_hash[:b] == hash['b'], false
    assert_equal hash['b'].start_with?('__!jsone'), true


    src_hash2 = src_hash.merge(d: "foox", e: "foo")
    File.write(src, JSON.pretty_generate(src_hash2))

    JSONe.write_key(key) # write down key as merge_with_encrypted
    dest = JSONe.encrypt_file(src, key)
    hash2 = JSON.parse(File.read(dest))

    assert_equal hash['b'], hash2['b'] # same cipher 
    assert_equal hash['d'] == hash2['d'], false # value changed, so cipher
    assert_equal hash2['e'] != nil, true

    new_key = JSONe.gen_key
    dest = JSONe.encrypt_file(src, new_key)
    hash3 = JSON.parse(File.read(dest))
    assert_equal hash2['b'] == hash3['b'], false # new cipher (new key is used)
    
    #dest = JSONe.encrypt_file(src, key, force: true)
    #hash3 = JSON.parse(File.read(dest))
    #assert_equal hash2['b'] == hash3['b'], false # new cipher (force)
    
    #puts hash2['b']
    #puts hash3['b']
    #puts dest
  end
end
