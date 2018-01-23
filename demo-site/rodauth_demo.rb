require 'roda'
require 'sequel/core'
require 'mail'
require 'securerandom'

module RodauthDemo
class App < Roda
  if url = ENV.delete('RODAUTH_DATABASE_URL') || ENV.delete('DATABASE_URL')
    DB = Sequel.connect(url)
  else
    DB = Sequel.sqlite
    Sequel.extension :migration
    Sequel::Migrator.run(DB, File.expand_path('../../spec/migrate_travis', __FILE__))
  end
  DB.extension :date_arithmetic
  DB.freeze

  ::Mail.defaults do
    delivery_method :test
  end

  opts[:root] = File.dirname(__FILE__)

  MAILS = {}
  SMS = {}
  MUTEX = Mutex.new

  secret = ENV.delete('RODAUTH_SESSION_SECRET') || ENV.delete('SESSION_SECRET') || SecureRandom.random_bytes(30)
  use Rack::Session::Cookie, :secret=>secret, :key => '_rodauth_demo_session'
  plugin :render, :escape=>true
  plugin :hooks

  plugin :csrf, :skip_if => lambda{|req| req.env['CONTENT_TYPE'] =~ /application\/json/}
  plugin :rodauth, :json=>true do
    db DB
    enable :change_login, :change_password, :close_account, :create_account,
           :lockout, :login, :logout, :remember, :reset_password, :verify_account,
           :otp, :recovery_codes, :sms_codes, :password_complexity,
           :disallow_password_reuse, :password_expiration, :password_grace_period,
           :account_expiration, :single_session, :jwt, :session_expiration,
           :verify_account_grace_period, :verify_login_change, :change_password_notify
    max_invalid_logins 2
    allow_password_change_after 60
    verify_account_grace_period 300
    verify_account_set_password? true
    account_password_hash_column :ph
    title_instance_variable :@page_title
    only_json? false
    json_response_custom_error_status? true
    jwt_secret secret
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
    rodauth.check_session_expiration
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
end
