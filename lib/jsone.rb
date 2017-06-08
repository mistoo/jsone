# frozen_string_literal: true
require 'json'
require 'base64'
require 'rbnacl'
require 'hashdiff'

module JSONe
  PUBLICKEY_KEY = "__jsone_public_key"
  ARRAY_KEY = "__jsone_array"
  CIPHER_PREFIX = "__!jsone__"
  KEYDIR = ENV['JSONE_KEYDIR'] || "/etc/jsone/keys"
  @verbose = 0
  
  def self.debug
    if @verbose > 1
      STDERR.puts "[JSONe:debug] #{yield}"
    end
  end

  def self.verbose=(v)
    @verbose = v
  end
  
  def self.log
    if @verbose > 0
      puts(yield)
    end
  end

  
  def self.gen_key
    RbNaCl::PrivateKey.generate
  end

  def self.to_hex(key)
    key.to_bytes.unpack('H*').first
  end
  
  def self.write_key(key, dir: KEYDIR)
    hex = to_hex(key.public_key)
    dest = "#{dir}/#{hex}"
    File.write(dest, to_hex(key))
    dest
  end

  def self.print_key(key)
    puts "public:  #{to_hex(key.public_key)}"
    puts "private: #{to_hex(key)}"
  end

  def self.load_key(public_key_hex, dir: KEYDIR)
    path = "#{dir}/#{public_key_hex}"
    return nil unless File.exist?(path)
    hex = File.read(path)
    bin = [ hex ].pack('H*')
    RbNaCl::Boxes::Curve25519XSalsa20Poly1305::PrivateKey.new(bin)
  end
  
  def self.box(key)
    RbNaCl::SimpleBox.from_keypair(key.public_key, key)
  end

  def self.encrypt_hash(box, hash)
    encrypted = {}
    hash.each do |key, val|
      skey = key.to_s
      if skey != ARRAY_KEY && skey.start_with?('__')
        # noop
      elsif val.is_a?(String) && !val.start_with?(CIPHER_PREFIX)
        cipher = Base64.encode64(box.encrypt(val))
        val = "#{CIPHER_PREFIX}#{cipher}"
      elsif val.is_a?(Hash)
        val = encrypt_hash(box, val)
      elsif val.is_a?(Array)
        val = val.map{ |v|
          v = encrypt_hash(box, v) if v.is_a?(Hash)
          v
        }
      end
      encrypted[key] = val
    end
    encrypted
  end

  def self.decrypt_hash(box, hash)
    decrypted = {}
    hash.each do |key, val|
      if val.is_a?(String) && val.start_with?(CIPHER_PREFIX)
        c = Base64.decode64(val[CIPHER_PREFIX.size..-1])
        val = box.decrypt(c)
      elsif val.is_a?(Hash)
        val = decrypt_hash(box, val)
      elsif val.is_a?(Array)
        val = val.map{ |v|
          v = decrypt_hash(box, v) if v.is_a?(Hash)
          v
        }
      end
      decrypted[key] = val
    end
    decrypted
  end

  def self.encrypt(hash, key, add_key: true)
    encrypted = encrypt_hash(box(key), hash)
    if add_key
      e = {}
      e[PUBLICKEY_KEY] = to_hex(key.public_key)
      e.merge! encrypted
      encrypted = e
    end
    encrypted
  end

  def self.key_from_hash(hash)
    public_hex = hash[PUBLICKEY_KEY]
    raise RuntimeError, "no key found (#{PUBLICKEY_KEY})" if public_hex.nil?
    key = load_key(public_hex)
    raise RuntimeError, "#{public_hex}: no such key found (#{KEYDIR})" if key.nil?
    key
  end
    
  def self.decrypt(hash, key = nil)
    key = key_from_hash(hash) if key.nil?
    decrypt_hash(box(key), hash)
  end


  def self.merge_with_encrypted(enc_path, hash, key)
    encrypted = JSON.parse(File.read(enc_path))
    decrypted = decrypt(encrypted)
    
    diff = HashDiff.diff(decrypted, hash).select{ |e| e[1] != PUBLICKEY_KEY }
    debug{ "prev #{decrypted}\ncurrent #{hash}\ndiff= #{diff}" }
      
    if encrypted[PUBLICKEY_KEY] == to_hex(key.public_key)
      if diff.size.zero?
        log{ "* #{enc_path}: file unchanged" }
        hash = {}
      else
        hash = HashDiff.patch!(encrypted, diff)
      end
    end
    hash
  end

  def self.encrypt_file(path, key = nil, force: false, output: nil)
    hash = JSON.parse(File.read(path))
    if hash.is_a?(Array)
      hash = Hash[ARRAY_KEY, hash]
    end
    key = key_from_hash(hash) if key.nil?

    dest = "#{path}e"
    if File.exist?(dest) && !force
      begin
        merged = merge_with_encrypted(dest, hash, key)
        if merged.size.zero?
          return dest
        end
        hash = merged
      rescue
        raise
      end
    end

    log{ "* encrypting #{path} with #{to_hex(key.public_key)}" }
    encrypted = encrypt(hash, key)
    
    if output.is_a?(IO)
      output.puts JSON.pretty_generate(encrypted)
      nil
    else
      File.write(dest, JSON.pretty_generate(encrypted))
      dest
    end
  end

  def self.decrypt_file(path, output: nil)
    unless path.end_with?('.jsone')
      raise ArgumentError, "encrypted file must have .jsone extension"
    end
    dest = path.sub(/e$/, '')
    fail if dest == path
    
    log{ "* decrypting #{path}" }
    hash = JSON.parse(File.read(path))
    decrypted = decrypt(hash)
    
    if decrypted.has_key?(ARRAY_KEY)
      decrypted = decrypted[ARRAY_KEY]
    end
    
    if output.is_a?(IO)
      output.puts JSON.pretty_generate(decrypted)
      nil
    else
      File.write(dest, JSON.pretty_generate(decrypted))
      dest
    end    
  end
end
  
