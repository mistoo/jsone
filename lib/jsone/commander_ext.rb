require 'commander/import'

# prevent OptionParser Officious to avoid -vvv (--version) shadowing
class OptionParser
  def add_officious
  end
end

# remove '-v' as --version alias as we want it to be used with --verbose
module Commander
  class Runner
    alias_method :original_global_option, :global_option
    def global_option(*args, &block)
      args.shift if args.size > 1 && args[1] == '--version'
      original_global_option(*args, &block)
    end
  end
end
