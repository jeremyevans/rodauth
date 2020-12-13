#!/usr/bin/env ruby
require 'erb'
require './lib/rodauth/version'
Dir.chdir(File.dirname(__FILE__))
erb = ERB.new(File.read('layout.erb'))
Dir['pages/*.erb'].each do |page|
  public_loc = "#{page.gsub(/\Apages\//, 'public/').sub('.erb', '.html')}"
  content = content = ERB.new(File.read(page)).result(binding)
  title = title = File.basename(page.sub('.erb', ''))
  File.open(public_loc, 'wb'){|f| f.write(erb.result(binding))}
end
