module JSONe
  module Cli
    extend self
    def get_key(pubkey)
      pubkey = ENV["JSONE_KEY"] unless pubkey
      return nil if pubkey.nil? || pubkey.empty?

      key = JSONe.load_key(pubkey)
      if key.nil?
        STDERR.puts "#{pubkey}: no such key found"
        exit!
      end
      key
    end

    def encrypt_file(path, key, force: false, output: nil)
      JSONe.encrypt_file(path, key, output: output, force: force)
    rescue JSON::ParserError => e
      STDERR.puts "#{path}: parse error: #{e.message}"
      false
    end

    def decrypt_file(path, output: nil, force: true)
      JSONe.decrypt_file(path, output: output)
    rescue JSON::ParserError => e
      STDERR.puts "#{path}: parse error: #{e.message}"
      false
    end

    def diff_file(path, key)
      diff = JSONe.diff_file(path, key)
      diff.each do |op, key, *values|
        puts "#{op} #{key}: #{values.is_a?(Array) ? values.join(' => ') : values}"
      end
      diff.size > 0
    rescue JSON::ParserError => e
      STDERR.puts "#{path}: parse error: #{e.message}"
      nil
    end

    def process_args(args, extension)
      args.each do |path|
        if File.directory?(path)
          pattern = File.join(path, "**/*#{extension}")
          puts pattern if ENV['VERBOSE']
          Dir.glob(pattern) do |file|
            puts file if ENV['VERBOSE']
            yield file
          end
        else
          yield path
        end
      end
    end
  end
end
