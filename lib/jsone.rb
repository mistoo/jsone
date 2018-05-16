# frozen_string_literal: true

require "json"
require "base64"
require "rbnacl"
require "hashdiff"

module JSONe
  ENCRYPTED_EXTENSION = '.jsone'.freeze
  PUBLICKEY_KEY = "__jsone_public_key".freeze
  ARRAY_KEY = "__jsone_array".freeze
  CIPHER_PREFIX = "__!jsone__".freeze
  KEYDIR = ENV["JSONE_KEYDIR"] || "/etc/jsone/keys"
  @verbose = 0

  def self.verbose=(v)
    @verbose = v
  end

  def self.debug
    STDERR.puts "[JSONe:debug] #{yield}" if @verbose > 1
  end
  private_class_method :debug

  def self.log
    puts(yield) if @verbose > 0
  end
  private_class_method :log

  def self.gen_key
    RbNaCl::PrivateKey.generate
  end

  def self.to_hex(key)
    key.to_bytes.unpack("H*").first
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
    bin = [hex].pack("H*")
    RbNaCl::Boxes::Curve25519XSalsa20Poly1305::PrivateKey.new(bin)
  end

  def self.box(key)
    RbNaCl::SimpleBox.from_keypair(key.public_key, key)
  end
  private_class_method :box

  def self.encrypt_hash(box, hash)
    encrypted = {}
    hash.each do |key, val|
      skey = key.to_s
      if skey != ARRAY_KEY && skey.start_with?("__")
        # noop
      elsif val.is_a?(String) && !val.start_with?(CIPHER_PREFIX)
        cipher = Base64.encode64(box.encrypt(val))
        val = "#{CIPHER_PREFIX}#{cipher}"
      elsif val.is_a?(Hash)
        val = encrypt_hash(box, val)
      elsif val.is_a?(Array)
        val = val.map do |v|
          v = encrypt_hash(box, v) if v.is_a?(Hash)
          v
        end
      end
      encrypted[key] = val
    end
    encrypted
  end
  private_class_method :encrypt_hash

  def self.decrypt_hash(box, hash)
    decrypted = {}
    hash.each do |key, val|
      if val.is_a?(String) && val.start_with?(CIPHER_PREFIX)
        c = Base64.decode64(val[CIPHER_PREFIX.size..-1])
        val = box.decrypt(c).force_encoding('utf-8')
      elsif val.is_a?(Hash)
        val = decrypt_hash(box, val)
      elsif val.is_a?(Array)
        val = val.map do |v|
          v = decrypt_hash(box, v) if v.is_a?(Hash)
          v
        end
      end
      decrypted[key] = val
    end
    decrypted
  end
  private_class_method :decrypt_hash

  def self.encrypt(hash, key, add_key: true)
    encrypted = encrypt_hash(box(key), hash)
    if add_key
      e = {}
      hex_key = to_hex(key.public_key)
      e[PUBLICKEY_KEY] = nil # top placeholder
      e.merge! encrypted
      e[PUBLICKEY_KEY] = hex_key
      encrypted = e
    end
    encrypted
  end

  def self.key_from_hash(hash)
    public_hex = hash[PUBLICKEY_KEY]
    raise "no key found (#{PUBLICKEY_KEY})" if public_hex.nil?
    key = load_key(public_hex)
    raise "#{public_hex}: no such key found (#{KEYDIR})" if key.nil?
    key
  end
  private_class_method :key_from_hash

  def self.decrypt(hash, key = nil)
    key = key_from_hash(hash) if key.nil?
    decrypt_hash(box(key), hash)
  end

  def self.merge_with_encrypted(enc_path, hash, key)
    encrypted = JSON.parse(File.read(enc_path))
    decrypted = decrypt(encrypted)

    diff = HashDiff.diff(decrypted, hash).reject { |e| e[1] == PUBLICKEY_KEY }
    debug { "prev #{decrypted}\ncurrent #{hash}\ndiff= #{diff}" }

    if encrypted[PUBLICKEY_KEY] == to_hex(key.public_key)
      if diff.size.zero?

        hash = {}
      else
        hash = HashDiff.patch!(encrypted, diff)
      end
    end
    hash
  end
  private_class_method :merge_with_encrypted

  def self.read_json(path)
    hash = JSON.parse(File.read(path, :encoding => 'utf-8'))
    hash = Hash[ARRAY_KEY, hash] if hash.is_a?(Array)
    hash
  end
  private_class_method :read_json

  def self.write_hash(hash, output: nil)
    json = JSON.pretty_generate(hash)

    if output.is_a?(IO)
      output.puts json
      nil
    elsif output.is_a?(String)
      File.write(output, JSON.pretty_generate(hash))
      output
    else
      raise ArgumentError, "output must be IO or String"
    end
  end
  private_class_method :write_hash

  def self.encrypt_file(path, key = nil, force: false, output: nil)
    hash = read_json(path)
    key = key_from_hash(hash) if key.nil?

    dest = "#{path}e"
    if File.exist?(dest) && !force
      begin
        merged = merge_with_encrypted(dest, hash, key)
        if merged.size.zero?
          log { "* #{dest}: file unchanged" }
          return dest
        end
        hash = merged
      rescue
        log { "* failed to decrypt previously encrypted file; data will be re-encrypted" }
      end
    end

    log { "* encrypting #{path} with #{to_hex(key.public_key)}" }
    encrypted = encrypt(hash, key)

    write_hash(encrypted, output: output || dest)
  end

  def self.decrypt_file(path, output: nil, force: true)
    raise ArgumentError, "encrypted file without .jsone extension" unless path.end_with?(".jsone")
    dest = path.sub(/e$/, "")
    raise "internal error" if dest == path

    log { "* decrypting #{path} to #{dest}" }
    hash = read_json(path)
    decrypted = decrypt(hash)
    decrypted = decrypted[ARRAY_KEY] if decrypted.key?(ARRAY_KEY)

    write_hash(decrypted, output: output || dest)
  end

  def self.diff_file(path, key = nil)
    hash = read_json(path)
    key = key_from_hash(hash) if key.nil?

    dest = "#{path}e"
    return nil unless File.exist?(dest)

    encrypted = JSON.parse(File.read(dest))
    decrypted = decrypt(encrypted)

    diff = HashDiff.diff(decrypted, hash).reject { |e| e[1] == PUBLICKEY_KEY }
    diff
  end
end
