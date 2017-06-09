module JSONe
  module Cli
    def self.get_key(pubkey)
      pubkey = ENV["JSONE_KEY"] unless pubkey
      return nil if pubkey.nil? || pubkey.empty?

      key = JSONe.load_key(pubkey)
      if key.nil?
        STDERR.puts "#{pubkey}: no such key found"
        exit!
      end
      key
    end

    def self.encrypt_file(path, key, force: false, output: nil)
      JSONe.encrypt_file(path, key, output: output, force: force)
    rescue JSON::ParserError => e
      STDERR.puts "#{path}: parse error: #{e.message}"
    end

    def self.decrypt_file(path, output: nil)
      JSONe.decrypt_file(path, output: output)
    rescue JSON::ParserError => e
      STDERR.puts "#{path}: parse error: #{e.message}"
    end

    def self.process_args(args, extension = ".json")
      args.each do |path|
        if File.directory?(path)
          pattern = File.join(path, "**/*#{extension}")
          puts pattern
          Dir.glob(pattern) do |file|
            puts file
            yield file
          end
        else
          yield path
        end
      end
    end
  end
end
