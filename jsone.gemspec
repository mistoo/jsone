# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'jsone/version'

Gem::Specification.new do |spec|
  spec.name          = "jsone"
  spec.version       = JSONe::VERSION
  spec.authors       = ["mis@pld-linux.org"]
  spec.email         = ["mis@pld-linux.org"]
  spec.summary       = %q{Asymmetric keywise encryption for JSON}
  spec.description   = %q{Secret management by encrypting values in a JSON hash with a public/private keypair}
  spec.homepage      = "http://github.com/mistoo/jsone"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.3.0'
  spec.add_runtime_dependency 'rbnacl'
  spec.add_runtime_dependency 'commander'
  spec.add_runtime_dependency 'dotenv'
  spec.add_runtime_dependency 'hashdiff'
  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest"
end
