require_relative 'spec_helper'

describe 'Rodauth audit_logging feature' do
  ds = DB[:account_authentication_audit_logs].reverse(:id)

  it "should handle audit logging of all actions" do
    rodauth do
      enable :login, :logout, :audit_logging
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    account_id, at, message, metadata = ds.get([:account_id, :at, :message, :metadata])
    account_id.must_equal DB[:accounts].get(:id)
    at = Time.parse(at) unless at.is_a?(Time)
    at.must_be(:>, Time.now - 86400)
    message.must_equal 'login'
    metadata.must_be_nil

    logout
    ds.get(:message).must_equal 'logout'

    login(:pass=>'012345678')
    ds.get(:message).must_equal 'login_failure'
  end

  it "should allow customizing of audit log messages and metadata" do
    rodauth do
      enable :login, :logout, :audit_logging
      audit_log_message_for :login, "Login Ahoy!"
      audit_log_message_for :login_failure do
        "Login failure for #{param(login_param)}"
      end
      audit_log_metadata_for :logout, {'details'=>'A wild logout appears!'}
      audit_log_metadata_for :login_failure do
        {'never_do_this'=>param(password_param)}
      end
      audit_log_message_default do |action|
        action.to_s.upcase
      end
      audit_log_metadata_default('nothing'=>'specific')
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    account_id, at, message, metadata = ds.get([:account_id, :at, :message, :metadata])
    account_id.must_equal DB[:accounts].get(:id)
    at = Time.parse(at) unless at.is_a?(Time)
    at.must_be(:>, Time.now - 86400)
    message.must_equal 'Login Ahoy!'
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata.must_equal('nothing'=>'specific')

    logout
    message, metadata = ds.get([:message, :metadata])
    message.must_equal 'LOGOUT'
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata.must_equal('details'=>'A wild logout appears!')

    login(:pass=>'012345678')
    message, metadata = ds.get([:message, :metadata])
    message.must_equal 'Login failure for foo@example.com'
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata.must_equal('never_do_this'=>'012345678')
  end
end
