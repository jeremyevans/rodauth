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
    Sequel::Migrator.run(DB, File.expand_path('../../spec/migrate_ci', __FILE__))
  end
  if ENV.delete('RODAUTH_DEMO_LOGGER')
    require 'logger'
    DB.loggers << Logger.new($stdout)
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

  plugin :render, :escape=>true
  plugin :request_aref, :raise
  plugin :hooks
  plugin :flash
  plugin :common_logger
  plugin :route_csrf

  secret = ENV.delete('RODAUTH_SESSION_SECRET') || SecureRandom.random_bytes(64)
  plugin :sessions, :secret=>secret, :key=>'rodauth-demo.session'

  plugin :rodauth, :json=>true, :csrf=>:route_csrf do
    db DB
    enable :change_login, :change_password, :close_account, :create_account,
           :lockout, :login, :logout, :remember, :reset_password, :verify_account,
           :otp, :recovery_codes, :sms_codes, :disallow_common_passwords,
           :disallow_password_reuse, :password_grace_period, :active_sessions, :jwt,
           :verify_login_change, :change_password_notify, :confirm_password,
           :email_auth
    enable :webauthn, :webauthn_login if ENV["RODAUTH_WEBAUTHN"]
    enable :webauthn_verify_account if ENV["RODAUTH_WEBAUTHN_VERIFY_ACCOUNT"]
    max_invalid_logins 2
    account_password_hash_column :ph
    title_instance_variable :@page_title
    only_json? false
    jwt_secret(secret)
    hmac_secret secret
    sms_send do |phone_number, message|
      MUTEX.synchronize{SMS[session_value] = "Would have sent the following SMS to #{phone_number}: #{message}"}
    end
  end

  plugin :error_handler do |e|
    @page_title = "Internal Server Error"
    view :content=>"#{h e.class}: #{h e.message}<br />#{e.backtrace.map{|line| h line}.join("<br />")}"
  end

  plugin :not_found do
    @page_title = "File Not Found"
    view :content=>""
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
    check_csrf! unless r.env['CONTENT_TYPE'] =~ /application\/json/
    rodauth.load_memory
    rodauth.check_active_session
    r.rodauth

    r.root do
      view 'index'
    end
  end
  
  freeze
end
end
