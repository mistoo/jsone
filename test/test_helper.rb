$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)

require 'tmpdir'
require 'fileutils'
require 'rubygems'

tmpdir = "#{Dir.tmpdir}/jsonetests"
FileUtils.rm_f tmpdir 
FileUtils.mkdir_p tmpdir
ENV['JSONE_KEYDIR'] = tmpdir

require 'jsone'
require 'minitest/autorun'
