#!/usr/bin/env ruby
#
# Copyright (c) 2018 joshua stein <jcs@jcs.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

require File.realpath(File.dirname(__FILE__) + "/../lib/rubywarden.rb")
require "getoptlong"

def usage
  puts "usage: #{$0} -u user@example.com"
  exit 1
end

username = nil

begin
  GetoptLong.new(
    [ "--user", "-u", GetoptLong::REQUIRED_ARGUMENT ],
  ).each do |opt,arg|
    case opt
    when "--user"
      username = arg
    end
  end

rescue GetoptLong::InvalidOption
  usage
end

if !username
  usage
end

@u = User.find_by_email(username)
if !@u
  raise "can't find existing User record for #{username.inspect}"
end

print "master password for #{@u.email}: "
system("stty -echo")
password = STDIN.gets.chomp
system("stty echo")
print "\n"

unless @u.has_password_hash?(Bitwarden.hashPassword(password, @u.email,
Bitwarden::KDF::TYPES[@u.kdf_type], @u.kdf_iterations))
  raise "master password does not match stored hash"
end

new_master = nil
new_master_conf = nil
new_master_hint = nil

while new_master.to_s == "" || (new_master != new_master_conf)
  print "new master password: "
  system("stty -echo")
  new_master = STDIN.gets.chomp
  system("stty echo")
  print "\n"

  print "new master password (again): "
  system("stty -echo")
  new_master_conf = STDIN.gets.chomp
  system("stty echo")
  print "\n"

  if new_master == new_master_conf
    print "new master password hint (optional): "
    system("stty -echo")
    new_master_hint = STDIN.gets.chomp
    system("stty echo")
    print "\n"
  else
    puts "error: passwords do not match"
  end
end

new_kdf_iterations = nil
while new_kdf_iterations.to_s == ""
  print "kdf iterations (currently #{@u.kdf_iterations}, default " <<
    "#{Bitwarden::KDF::DEFAULT_ITERATIONS[@u.kdf_type]}): "
  new_kdf_iterations = STDIN.gets.chomp

  if new_kdf_iterations.to_s == ""
    new_kdf_iterations = Bitwarden::KDF::DEFAULT_ITERATIONS[@u.kdf_type]
    break
  elsif !(r = Bitwarden::KDF::ITERATION_RANGES[@u.kdf_type]).
  include?(new_kdf_iterations.to_i)
    puts "iterations must be between #{r}"
    new_kdf_iterations = nil
  else
    new_kdf_iterations = new_kdf_iterations.to_i
    break
  end
end

@u.update_master_password(password, new_master, new_kdf_iterations)
@u.password_hint = new_master_hint
if !@u.save
  puts "error saving new password"
end

puts "master password changed"
