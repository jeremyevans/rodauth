require_relative 'spec_helper'

begin
  require 'webauthn/fake_client'
rescue LoadError
else
describe 'Rodauth webauthn feature' do
  it "should handle webauthn authentication" do
    hmac_secret = '123'
    before_setup = nil
    before_remove = nil
    rodauth do
      enable :login, :logout, :webauthn
      hmac_secret do
        hmac_secret
      end
      before_webauthn_setup do
        before_setup.call if before_setup
      end
      before_webauthn_remove do
        before_remove.call if before_remove
      end
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/webauthn-auth' unless rodauth.authenticated?
        view :content=>"With WebAuthn"
      else    
        view :content=>"Without WebAuthn"
      end
    end

    login
    page.html.must_include('Without WebAuthn')
    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)
    valid_webauthn_client = WebAuthn::FakeClient.new(origin)
    bad_origin_client = WebAuthn::FakeClient.new(origin.sub('com', 'gov'))

    %w'/webauthn-auth /webauthn-remove'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'This account has not been setup for WebAuthn authentication'
      page.current_path.must_equal '/webauthn-setup'
    end

    page.title.must_equal 'Setup WebAuthn Authentication'
    fill_in 'Password', :with=>'asdf'
    fill_in 'webauthn_setup', :with=>'{}'
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'
    page.html.must_include 'invalid password'

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json[0...-1]
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge+'1').to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>bad_origin_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    hmac_secret = '321'
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'
    hmac_secret = '123'
    visit page.current_path

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    webauthn_hash = webauthn_client.create(challenge: challenge)
    fill_in 'webauthn_setup', :with=>webauthn_hash.to_json
    before_setup = lambda do
      DB[:account_webauthn_keys].insert(:account_id=>DB[:accounts].get(:id), :webauthn_id=>webauthn_hash["rawId"], :public_key=>'1', :sign_count=>1)
    end
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'
    before_setup = nil

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>valid_webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With WebAuthn'

    logout
    login

    page.title.must_equal 'Authenticate Using WebAuthn'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json[0...-1]
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge+'1').to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>bad_origin_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    hmac_secret = '321'
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'
    hmac_secret = '123'
    visit page.current_path

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    sign_count = DB[:account_webauthn_keys].get(:sign_count)
    DB[:account_webauthn_keys].update(:sign_count=>sign_count + 10)
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'
    DB[:account_webauthn_keys].update(:sign_count=>sign_count)
    visit page.current_path

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>valid_webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.current_path.must_equal '/'
    page.html.must_include 'With WebAuthn'
    
    visit '/webauthn-remove'
    page.title.must_equal 'Remove WebAuthn Authenticator'

    choose "Last Use: "
    click_button 'Remove WebAuthn Authenticator'
    page.find('#error_flash').text.must_equal "Error removing WebAuthn authenticator"
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Remove WebAuthn Authenticator'
    page.find('#error_flash').text.must_equal "Error removing WebAuthn authenticator"
    page.html.must_include 'must select valid webauthn authenticator to remove'
    
    fill_in 'Password', :with=>'0123456789'
    choose "Last Use: "
    key_row = DB[:account_webauthn_keys].first
    before_remove = lambda do
      DB[:account_webauthn_keys].delete
    end
    click_button 'Remove WebAuthn Authenticator'
    page.find('#error_flash').text.must_equal "Error removing WebAuthn authenticator"
    page.html.must_include 'must select valid webauthn authenticator to remove'
    before_remove = nil
    DB[:account_webauthn_keys].insert(key_row)
    visit page.current_path

    fill_in 'Password', :with=>'0123456789'
    choose "Last Use: "
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'Without WebAuthn'

    visit '/webauthn-auth-js'
    page.body.must_include File.binread("javascript/webauthn_auth.js")

    visit '/webauthn-setup-js'
    page.body.must_include File.binread("javascript/webauthn_setup.js")
  end

  it "should allow namespaced webauthn authentication without password requirements" do
    rodauth do
      enable :login, :logout, :webauthn
      prefix "/auth"
      hmac_secret '123'
      two_factor_modifications_require_password? false
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.on "auth" do
        r.rodauth
      end

      r.redirect '/auth/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/auth/webauthn-auth' unless rodauth.authenticated?
        view :content=>"With WebAuthn"
      else    
        view :content=>"Without WebAuthn"
      end
    end

    login
    page.html.must_include('Without WebAuthn')
    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    visit '/auth/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With WebAuthn'

    visit '/auth/logout'
    click_button 'Logout'
    login

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.current_path.must_equal '/'
    page.html.must_include 'With WebAuthn'

    visit '/auth/webauthn-remove'
    choose "Last Use: "
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'Without WebAuthn'
  end

  it "should remove webauthn data when closing accounts" do
    rodauth do
      enable :login, :webauthn, :close_account
      hmac_secret '123'
      modifications_require_password? false
      two_factor_modifications_require_password? false
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth
      rodauth.require_authentication
      rodauth.require_two_factor_setup
      view :content=>"With WebAuthn"
    end

    login
    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    DB[:account_webauthn_user_ids].wont_be_empty
    DB[:account_webauthn_keys].wont_be_empty

    visit '/close-account'
    click_button 'Close Account'
    DB[:account_webauthn_user_ids].must_be_empty
    DB[:account_webauthn_keys].must_be_empty
  end

  it "should handle registering and using multiple webauthn authenticators" do
    rodauth do
      enable :login, :logout, :webauthn
      hmac_secret '123'
      two_factor_modifications_require_password? false
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      rodauth.require_authentication

      if rodauth.two_factor_authentication_setup?
        view :content=>"With WebAuthn"
      else    
        view :content=>"Without WebAuthn"
      end
    end

    login
    origin = first_request.base_url
    webauthn_client1 = WebAuthn::FakeClient.new(origin)
    webauthn_client2 = WebAuthn::FakeClient.new(origin)

    visit '/multifactor-manage'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    webauthn_hash = webauthn_client1.create(challenge: challenge)
    fill_in 'webauthn_setup', :with=>webauthn_hash.to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'

    visit '/multifactor-manage'
    click_link 'Setup WebAuthn Authentication'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client2.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'

    logout
    login

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client1.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    logout
    login

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client2.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    visit '/multifactor-manage'
    click_link 'Remove WebAuthn Authenticator'

    choose "rodauth-webauthn-remove-#{webauthn_hash["rawId"]}"
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'With WebAuthn'

    logout
    login

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client1.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client2.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    visit '/multifactor-manage'
    click_link 'Remove WebAuthn Authenticator'

    choose "Last Use"
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'Without WebAuthn'
  end

  it "should handle webauthn authentication with invalid sign counts if configured" do
    default_sign_count = false
    rodauth do
      enable :login, :logout, :webauthn
      hmac_secret '123'
      two_factor_modifications_require_password? false
      handle_webauthn_sign_count_verification_error do
        super() if default_sign_count
      end
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth
      rodauth.require_authentication
      rodauth.require_two_factor_setup
      view :content=>"With WebAuthn"
    end

    login
    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'

    logout
    login

    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    DB[:account_webauthn_keys].update(:sign_count=>Sequel[:sign_count] + 10)
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.current_path.must_equal '/'
    page.html.must_include 'With WebAuthn'

    logout
    login

    default_sign_count = true
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    DB[:account_webauthn_keys].update(:sign_count=>Sequel[:sign_count] + 10)
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'
  end

  it "should allow webauthn authentication via jwt" do
    rodauth do
      enable :login, :logout, :webauthn
      hmac_secret '123'
    end
    first_request = nil
    roda(:jwt) do |r|
      first_request ||= r
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

    origin = first_request.base_url
    bad_client = WebAuthn::FakeClient.new(origin)
    webauthn_client1 = WebAuthn::FakeClient.new(origin)
    webauthn_client2 = WebAuthn::FakeClient.new(origin)

    %w'/webauthn-auth /webauthn-remove'.each do |path|
      json_request(path).must_equal [403, {'error'=>'This account has not been setup for WebAuthn authentication'}]
    end

    res = json_request('/webauthn-setup', :password=>'0123456789')
    setup_json = res[1].delete("webauthn_setup")
    challenge = res[1].delete("webauthn_setup_challenge")
    challenge_hmac = res[1].delete("webauthn_setup_challenge_hmac")
    res.must_equal [422, {'error'=>'Error setting up WebAuthn authentication', "field-error"=>["webauthn_setup", 'invalid webauthn setup param']}] 

    res = json_request('/webauthn-setup', :password=>'123456', :webauthn_setup=>'{}')
    res.must_equal [401, {'error'=>'Error setting up WebAuthn authentication', "field-error"=>["password", 'invalid password']}] 

    res = json_request('/webauthn-setup', :password=>'0123456789', :webauthn_setup=>bad_client.create(challenge: setup_json['challenge']), :webauthn_setup_challenge=>challenge+'1', :webauthn_setup_challenge_hmac=>challenge_hmac)
    res.must_equal [422, {'error'=>'Error setting up WebAuthn authentication', "field-error"=>["webauthn_setup", 'invalid webauthn setup param']}] 

    res = json_request('/webauthn-setup', :password=>'0123456789', :webauthn_setup=>bad_client.create(challenge: setup_json['challenge'] + '1'), :webauthn_setup_challenge=>challenge, :webauthn_setup_challenge_hmac=>challenge_hmac)
    res.must_equal [422, {'error'=>'Error setting up WebAuthn authentication', "field-error"=>["webauthn_setup", 'invalid webauthn setup param']}] 

    webauthn_hash1 = webauthn_client1.create(challenge: setup_json['challenge'])
    res = json_request('/webauthn-setup', :password=>'0123456789', :webauthn_setup=>webauthn_hash1, :webauthn_setup_challenge=>challenge, :webauthn_setup_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'WebAuthn authentication is now setup'}]

    res = json_request('/webauthn-setup', :password=>'0123456789')
    setup_json = res[1].delete("webauthn_setup")
    challenge = res[1].delete("webauthn_setup_challenge")
    challenge_hmac = res[1].delete("webauthn_setup_challenge_hmac")
    res.must_equal [422, {'error'=>'Error setting up WebAuthn authentication', "field-error"=>["webauthn_setup", 'invalid webauthn setup param']}] 

    webauthn_hash2 = webauthn_client2.create(challenge: setup_json['challenge'])
    res = json_request('/webauthn-setup', :password=>'0123456789', :webauthn_setup=>webauthn_hash2, :webauthn_setup_challenge=>challenge, :webauthn_setup_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'WebAuthn authentication is now setup'}]
    json_request.must_equal [200, [1]]

    json_logout
    json_login
    json_request.must_equal [200, [2]]

    res = json_request('/webauthn-auth')
    auth_json = res[1].delete("webauthn_auth")
    challenge = res[1].delete("webauthn_auth_challenge")
    challenge_hmac = res[1].delete("webauthn_auth_challenge_hmac")
    res.must_equal [422, {"field-error"=>["webauthn_auth", "invalid webauthn authentication param"], "error"=>"Error authenticating using WebAuthn"}]

    res = json_request('/webauthn-auth', :webauthn_auth=>webauthn_client1.get(challenge: auth_json['challenge']), :webauthn_auth_challenge=>challenge, :webauthn_auth_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'You have been multifactor authenticated'}]
    json_request.must_equal [200, [1]]

    json_logout
    json_login

    res = json_request('/webauthn-auth')
    auth_json = res[1].delete("webauthn_auth")
    challenge = res[1].delete("webauthn_auth_challenge")
    challenge_hmac = res[1].delete("webauthn_auth_challenge_hmac")
    res.must_equal [422, {"field-error"=>["webauthn_auth", "invalid webauthn authentication param"], "error"=>"Error authenticating using WebAuthn"}]

    res = json_request('/webauthn-auth', :webauthn_auth=>webauthn_client2.get(challenge: auth_json['challenge']), :webauthn_auth_challenge=>challenge, :webauthn_auth_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'You have been multifactor authenticated'}]
    json_request.must_equal [200, [1]]

    res = json_request('/webauthn-remove', :password=>'0123456789')
    remove_ids = res[1].delete("webauthn_remove")
    remove_ids[webauthn_hash1['rawId']].must_include(Time.now.strftime('%F'))
    remove_ids[webauthn_hash2['rawId']].must_include(Time.now.strftime('%F'))
    remove_ids.length.must_equal 2
    res.must_equal [422, {"field-error"=>["webauthn_remove", "must select valid webauthn authenticator to remove"], "error"=>"Error removing WebAuthn authenticator"}]

    res = json_request('/webauthn-remove', :password=>'012345678', :webauthn_remove=>'1')
    res[1].delete("webauthn_remove").must_be_nil
    res.must_equal [401, {"field-error"=>["password", "invalid password"], "error"=>"Error removing WebAuthn authenticator"}]

    res = json_request('/webauthn-remove', :password=>'0123456789', :webauthn_remove=>webauthn_hash1['rawId'])
    res.must_equal [200, {'success'=>'WebAuthn authenticator has been removed'}]
    json_request.must_equal [200, [1]]

    res = json_request('/webauthn-remove', :password=>'0123456789', :webauthn_remove=>webauthn_hash2['rawId'])
    res.must_equal [200, {'success'=>'WebAuthn authenticator has been removed'}]
    json_request.must_equal [200, [3]]
  end
end
end
