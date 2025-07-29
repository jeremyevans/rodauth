require_relative 'spec_helper'

require 'rotp'

describe 'Rodauth otp_unlock feature' do
  secret_length = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length

  def reset_otp_last_use
    DB[:account_otp_keys].update(:last_use=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>600))
  end
  def reset_otp_unlock_next_attempt_after
    DB[:account_otp_unlocks].update(:next_auth_attempt_after=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>1))
  end

  it "should allow unlocking totp authentication" do
    rodauth do
      enable :login, :logout, :otp_unlock
      hmac_secret '123'
      otp_unlock_next_auth_attempt_refresh_label do
        super() + otp_unlock_refresh_tag
      end
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/otp-auth' unless rodauth.authenticated?
        view :content=>"With 2FA"
      else    
        view :content=>"Without 2FA"
      end
    end

    visit '/otp-unlock'
    page.title.must_equal 'Login'

    login

    visit '/otp-unlock'
    page.title.must_equal 'Setup TOTP Authentication'

    login
    visit '/otp-setup'
    page.title.must_equal 'Setup TOTP Authentication'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With 2FA'

    reset_otp_last_use
    visit '/otp-unlock'
    page.find('#error_flash').text.must_equal 'TOTP authentication is not currently locked out'
    page.html.must_include 'With 2FA'

    logout
    login

    6.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>'foo'
      click_button 'Authenticate Using TOTP'
    end
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP to Unlock'
    reset_otp_unlock_next_attempt_after
    page.current_path.must_equal '/otp-unlock'
    visit '/multifactor-auth'
    page.current_path.must_equal '/otp-unlock'

    page.html.must_include "Consecutive successful authentications: 1"
    DB[:account_otp_unlocks].update(:next_auth_attempt_after=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>1000))
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP to Unlock'
    page.find('#error_flash').text.must_equal 'Deadline past for unlocking TOTP authentication'
    page.html.must_include "Consecutive successful authentications: 0"

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP to Unlock'
    reset_otp_unlock_next_attempt_after
    visit page.current_path

    page.html.must_include "Consecutive successful authentications: 1"
    DB[:account_otp_unlocks].update(:next_auth_attempt_after=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :seconds=>1000))
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP to Unlock'
    page.find('#error_flash').text.must_equal 'TOTP unlock attempt not yet available'
    page.html.must_include "Consecutive successful authentications: 1"
    page.title.must_equal 'Must Wait to Unlock TOTP Authentication'

    reset_otp_unlock_next_attempt_after
    visit page.current_path
    fill_in 'Authentication Code', :with=>'1'
    click_button 'Authenticate Using TOTP to Unlock'
    page.find('#error_flash').text.must_equal 'TOTP invalid authentication'

    page.html.must_include "Consecutive successful authentications: 0"
    reset_otp_unlock_next_attempt_after
    visit page.current_path
    fill_in 'Authentication Code', :with=>'1'
    click_button 'Authenticate Using TOTP to Unlock'
    page.find('#error_flash').text.must_equal 'TOTP invalid authentication'

    reset_otp_unlock_next_attempt_after
    visit page.current_path
    2.times do |i|
      page.title.must_equal 'Unlock TOTP Authentication'
      page.html.must_include "Consecutive successful authentications: #{i}"
      page.html.must_include 'Required consecutive successful authentications to unlock: 3'
      page.html.must_include "Deadline for next authentication: "
      fill_in 'Authentication Code', :with=>totp.now
      click_button 'Authenticate Using TOTP to Unlock'

      page.find('#notice_flash').text.must_equal 'TOTP successful authentication, more successful authentication needed to unlock'
      page.title.must_equal 'Must Wait to Unlock TOTP Authentication'
      page.html.must_include "Consecutive successful authentications: #{i+1}"
      page.html.must_include 'Required consecutive successful authentications to unlock: 3'
      page.html.must_include "Can attempt next authentication after: "
      page.html.must_include "Page will automatically refresh when authentication is possible."
      page.response_headers['refresh'].must_match(/\A1[012]\d\z/)
      page.html.must_match(/<meta http-equiv="refresh" content="1[012]\d">/)
      reset_otp_unlock_next_attempt_after
      visit page.current_path
    end

    page.html.must_include 'Consecutive successful authentications: 2'
    page.html.must_include 'Required consecutive successful authentications to unlock: 3'
    page.html.must_include "Deadline for next authentication: "
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP to Unlock'
    page.find('#notice_flash').text.must_equal 'TOTP authentication unlocked'
    page.current_path.must_equal '/otp-auth'
    page.title.must_equal 'Enter Authentication Code'
  end

  [:jwt, :json_no_enable].each do |json|
    use_json = true
    it "should allow unlock otp via #{json}" do
      rodauth do
        enable :login, :logout, :otp_unlock, :json
        json_response_success_key 'success'
        use_json?{use_json}
        only_json?{use_json}
        set_error_reason { |reason| json_response['reason'] = reason }
      end
      roda(json) do |r|
        r.rodauth

        if rodauth.logged_in?
          if rodauth.two_factor_authentication_setup?
            if rodauth.authenticated?
             [1]
            else
             [2]
            end
          else    
           [3]
          end
        else
          [4]
        end
      end

      json_request.must_equal [200, [4]]
      json_login
      json_request.must_equal [200, [3]]

      res = json_request('/otp-unlock')
      res.must_equal [403, {"reason"=>"two_factor_not_setup", "error"=>"This account has not been setup for multifactor authentication"}]

      secret = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).downcase
      totp = ROTP::TOTP.new(secret)

      res = json_request('/otp-setup', :password=>'0123456789', :otp=>totp.now, :otp_secret=>secret)
      res.must_equal [200, {'success'=>'TOTP authentication is now setup'}]
      reset_otp_last_use
      json_request.must_equal [200, [1]]

      json_logout
      json_login
      json_request.must_equal [200, [2]]

      res = json_request('/otp-unlock', :otp=>totp.now)
      res.must_equal [403, {"reason"=>"otp_not_locked_out", "error"=>"TOTP authentication is not currently locked out"}]

      5.times do
        res = json_request('/otp-auth', :otp=>'adsf')
        res.must_equal [401, {'reason'=>"invalid_otp_auth_code",'error'=>'Error logging in via TOTP authentication', "field-error"=>["otp", 'Invalid authentication code']}] 
      end

      res = json_request('/otp-auth', :otp=>'adsf')
      res.must_equal [403, {"reason"=>"otp_locked_out", "error"=>"TOTP authentication code use locked out due to numerous failures"}]
      range = (-15..15)

      res = json_request('/otp-unlock', :otp=>'adsf')
      range.must_include(Time.now.to_i + 900 - res[1].delete("next_attempt_after"))
      res.must_equal [403, {"reason"=>"otp_unlock_auth_failure", "error"=>"TOTP invalid authentication", "num_successes"=>0, "required_successes"=>3}]
      res = json_request('/otp-unlock', :otp=>totp.now)
      range.must_include(Time.now.to_i + 900 - res[1].delete("next_attempt_after"))
      res.must_equal [403, {"reason"=>"otp_unlock_not_yet_available", "error"=>"TOTP unlock attempt not yet available", "num_successes"=>0, "required_successes"=>3}]
      DB[:account_otp_unlocks].update(:next_auth_attempt_after=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :seconds=>-1000))
      res = json_request('/otp-unlock', :otp=>totp.now)
      res.must_equal [403, {"reason"=>"otp_unlock_deadline_passed", "error"=>"Deadline past for unlocking TOTP authentication"}]
      reset_otp_unlock_next_attempt_after

      if json == :json_no_enable
        use_json = false
        login
        visit '/otp-unlock'
        fill_in 'Authentication Code', :with=>'1'
        click_button 'Authenticate Using TOTP to Unlock'
        page.find('#error_flash').text.must_equal 'TOTP invalid authentication'
        reset_otp_unlock_next_attempt_after
        use_json = true
      end

      2.times do |i|
        res = json_request('/otp-unlock', :otp=>totp.now)
        range.must_include(Time.now.to_i + 120 - res[1].delete("next_attempt_after"))
        range.must_include(Time.now.to_i + 1020 - res[1].delete("deadline"))
        res.must_equal [200, {"success"=>"TOTP successful authentication, more successful authentication needed to unlock", "num_successes"=>i+1, "required_successes"=>3}]
        reset_otp_unlock_next_attempt_after
      end

      res = json_request('/otp-unlock', :otp=>totp.now)
      res.must_equal [200, {"success"=>"TOTP authentication unlocked"}]

    end
  end
end
