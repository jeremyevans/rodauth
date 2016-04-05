#!/usr/bin/env/ruby
require 'roda'
require 'erubis'
require 'tilt/erubis'
require 'sequel/core'
require 'mail'
$: << '../lib'

DB = Sequel.connect(ENV['DATABASE_URL'])

::Mail.defaults do
  delivery_method :test
end

class RodauthDemo < Roda
  MAILS = {}
  SMS = {}
  MUTEX = Mutex.new

  use Rack::Session::Cookie, :secret=>(ENV['SESSION_SECRET'] || SecureRandom.random_bytes(30)), :key => '_rodauth_demo_session'
  plugin :render, :escape=>true
  plugin :hooks

  plugin :csrf
  plugin :rodauth do
    enable :change_login, :change_password, :close_account, :create_account,
           :lockout, :login, :logout, :remember, :reset_password, :verify_account,
           :otp, :recovery_codes, :sms_codes, :password_complexity,
           :disallow_password_reuse, :password_expiration,
           :account_expiration, :single_session
    max_invalid_logins 2
    allow_password_change_after 60
    account_password_hash_column :ph
    title_instance_variable :@page_title
    sms_send do |phone_number, message|
      MUTEX.synchronize{SMS[session_value] = "Would have sent the following SMS to #{phone_number}: #{message}"}
    end
  end

  def last_sms_sent
    MUTEX.synchronize{SMS.delete(rodauth.session_value)}
  end

  def last_mail_sent
    MUTEX.synchronize{MAILS.delete(rodauth.session_value)}
  end

  after do
    Mail::TestMailer.deliveries.each do |mail|
      MUTEX.synchronize{MAILS[rodauth.session_value] = mail}
    end
    Mail::TestMailer.deliveries.clear
  end

  route do |r|
    rodauth.load_memory
    rodauth.update_last_activity
    if session['single_session_check']
      rodauth.check_single_session
    end
    r.rodauth

    r.root do
      view 'index'
    end

    r.post "single-session" do
      session['single_session_check'] = !r['d']
      r.redirect '/'
    end
  end
  
  freeze
end
