require_relative 'spec_helper'

require 'rodauth'

describe 'Rodauth.lib' do
  it "should support returning a Rodauth::Auth class usable as a library" do
    rodauth = Rodauth.lib do
      enable :login, :create_account, :change_password
      if ENV['RODAUTH_SEPARATE_SCHEMA']
        password_hash_table Sequel[:rodauth_test_password][:account_password_hashes]
        function_name do |name|
          "rodauth_test_password.#{name}"
        end
      end
      if ENV['RODAUTH_ALWAYS_ARGON2'] == '1'
        enable :argon2
      end
    end

    rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'0123456789').must_equal true
    rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'01234567').must_equal false
    rodauth.valid_login_and_password?(:login=>'foo3@example.com', :password=>'0123456789').must_equal false

    rodauth.create_account(:login=>'foo3@example.com', :password=>'sdkjnlsalkklsda').must_be_nil

    rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'0123456789').must_equal true
    rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'01234567').must_equal false
    rodauth.valid_login_and_password?(:login=>'foo3@example.com', :password=>'sdkjnlsalkklsda').must_equal true

    rodauth.change_password(:account_login=>'foo@example.com', :password=>'01234567').must_be_nil

    rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'0123456789').must_equal false
    rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'01234567').must_equal true
    rodauth.valid_login_and_password?(:login=>'foo3@example.com', :password=>'sdkjnlsalkklsda').must_equal true
  end
end
