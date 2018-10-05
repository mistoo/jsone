# frozen_string_literal: true

require "json"
require "base64"
require "rbnacl"
require "hashdiff"

module JSONe
  extend self
  ENCRYPTED_EXTENSION = '.jsone'
  RAW_EXTENSION = '.json'
  PUBLICKEY_KEY = "__jsone_public_key"
  ARRAY_KEY = "__jsone_array"
  CIPHER_PREFIX = "__!jsone__"
  KEYDIR = ENV.fetch("JSONE_KEYDIR", "/etc/jsone/keys")
  @verbose = 0

  def verbose=(v)
    @verbose = v
  end

  def debug
    STDERR.puts "[JSONe:debug] #{yield}" if @verbose > 1
  end
  private_class_method :debug

  def log
    puts(yield) if @verbose > 0
  end
  private_class_method :log

  def gen_key
    RbNaCl::PrivateKey.generate
  end

  def to_hex(key)
    key.to_bytes.unpack("H*").first
  end


  def write_key(key, dir: KEYDIR)
    hex = to_hex(key.public_key)
    dest = "#{dir}/#{hex}"
    File.write(dest, to_hex(key))
    dest
  end

  def print_key(key)
    puts "public:  #{to_hex(key.public_key)}"
    puts "private: #{to_hex(key)}"
  end

  def load_key(public_key_hex, dir: KEYDIR)
    path = "#{dir}/#{public_key_hex}"
    return nil unless File.exist?(path)
    hex = File.read(path)
    bin = [hex].pack("H*")
    RbNaCl::Boxes::Curve25519XSalsa20Poly1305::PrivateKey.new(bin)
  end

  def box(key)
    RbNaCl::SimpleBox.from_keypair(key.public_key, key)
  end
  private_class_method :box

  def encrypt_value(box, value)
    if value.is_a?(String)
      unless value.start_with?(CIPHER_PREFIX)
        cipher = Base64.encode64(box.encrypt(value))
        value = "#{CIPHER_PREFIX}#{cipher}"
      end
    elsif value.is_a?(Hash)
      value.each do |key, val|
        skey = key.to_s
        value[key] = encrypt_value(box, val)
      end
    elsif value.is_a?(Array)
      value.map!{ |val| encrypt_value(box, val) }
    end
    value
  end
  private_class_method :encrypt_value

  def encrypt_hash(box, hash)
    dest = Marshal.restore(Marshal.dump(hash))
    return encrypt_value(box, dest)
  end
  private_class_method :encrypt_hash

  def decrypt_value(box, value)
    if value.is_a?(String)
      if value.start_with?(CIPHER_PREFIX)
        c = Base64.decode64(value[CIPHER_PREFIX.size..-1])
        value = box.decrypt(c).force_encoding('utf-8')
      end
    elsif value.is_a?(Hash)
      value.each do |key, val|
        value[key] = decrypt_value(box, val)
      end
    elsif value.is_a?(Array)
      value.map!{ |val| decrypt_value(box, val) }
    end
    value
  end

  def decrypt_hash(box, hash)
    dest = Marshal.restore(Marshal.dump(hash))
    return decrypt_value(box, dest)
  end
  private_class_method :decrypt_hash

  def encrypt(hash, key, add_key: true)
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

  def key_from_hash(hash)
    public_hex = hash[PUBLICKEY_KEY]
    raise "no key found (#{PUBLICKEY_KEY})" if public_hex.nil?
    key = load_key(public_hex)
    raise "#{public_hex}: no such key found (#{KEYDIR})" if key.nil?
    key
  end
  private_class_method :key_from_hash

  def decrypt(hash, key = nil)
    key = key_from_hash(hash) if key.nil?
    decrypt_hash(box(key), hash)
  end

  def merge_with_encrypted(enc_path, hash, key)
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

  def read_json(path)
    hash = JSON.parse(File.read(path, :encoding => 'utf-8'))
    hash = Hash[ARRAY_KEY, hash] if hash.is_a?(Array)
    hash
  end
  private_class_method :read_json

  def write_hash(hash, output: nil)
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

  def encrypted_path(path)
    ext = File.extname(path)
    raise ArgumentError, "#{path} must end with #{RAW_EXTENSION}" if ext != RAW_EXTENSION
    path.sub(/#{ext}$/, ENCRYPTED_EXTENSION)
  end

  def raw_path(path)
    ext = File.extname(path)
    raise ArgumentError, "#{path} must end with #{ENCRYPTED_EXTENSION}" if ext != ENCRYPTED_EXTENSION
    path.sub(/#{ext}$/, RAW_EXTENSION)
  end

  def encrypt_file(path, key = nil, force: false, output: nil)
    hash = read_json(path)
    key = key_from_hash(hash) if key.nil?

    dest = encrypted_path(path)
    if File.exist?(dest) && !force
      begin
        merged = merge_with_encrypted(dest, hash, key)
        if merged.size.zero?
          log { "* #{dest}: file contents unchanged" }
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

  def decrypt_file(path, output: nil, force: true)
    dest = raw_path(path)
    raise "internal error" if dest == path

    log { "* decrypting #{path} to #{dest}" }
    hash = read_json(path)
    decrypted = decrypt(hash)
    decrypted = decrypted[ARRAY_KEY] if decrypted.key?(ARRAY_KEY)

    write_hash(decrypted, output: output || dest)
  end

  def diff_file(path, key = nil)
    hash = read_json(path)
    key = key_from_hash(hash) if key.nil?

    dest = encrypted_path(path)
    return nil unless File.exist?(dest)

    encrypted = JSON.parse(File.read(dest))
    decrypted = decrypt(encrypted)

    diff = HashDiff.diff(decrypted, hash).reject { |e| e[1] == PUBLICKEY_KEY }
    diff
  end
end
