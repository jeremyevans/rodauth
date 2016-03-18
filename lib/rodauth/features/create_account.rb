module Rodauth
  CreateAccount = Feature.define(:create_account) do
    depends :login
    route 'create-account'
    notice_flash 'Your account has been created'
    error_flash "There was an error creating your account"
    view 'create-account', 'Create Account'
    after
    button 'Create Account'
    additional_form_tags
    redirect

    auth_value_methods :create_account_autologin?, :create_account_link
    auth_methods :new_account, :save_account

    get_block do |r, auth|
      auth.create_account_view
    end

    post_block do |r, auth|
      login = r[auth.login_param].to_s
      password = r[auth.password_param].to_s
      auth._new_account(login)
      if login == r[auth.login_confirm_param]
        if password == r[auth.password_confirm_param]
          if auth.password_meets_requirements?(password)
            auth.transaction do
              if auth.save_account
                auth.set_password(password) unless auth.account_password_hash_column
                auth.after_create_account
                if auth.create_account_autologin?
                  auth.update_session
                end
                auth.set_notice_flash auth.create_account_notice_flash
                r.redirect(auth.create_account_redirect)
              else
                @login_error = auth.login_errors_message
              end
            end
          else
            @password_error = auth.password_does_not_meet_requirements_message
          end
        else
          @password_error = auth.passwords_do_not_match_message
        end
      else
        @login_error = auth.logins_do_not_match_message
      end

      auth.set_error_flash auth.create_account_error_flash
      auth.create_account_view
    end

    def create_account_link
      "<p><a href=\"#{prefix}/#{create_account_route}\">Create a New Account</a></p>"
    end

    def login_form_footer
      super + create_account_link
    end

    def create_account_autologin?
      false
    end

    def new_account(login)
      @account = account_model.new(login_column=>login)
      if account_password_hash_column
        account.set(account_password_hash_column=>password_hash(request[password_param].to_s))
      end
      unless skip_status_checks?
        account.set(account_status_id=>account_initial_status_value)
      end
      @account
    end
    
    def _new_account(login)
      @account = new_account(login)
    end

    def save_account
      account.save(:raise_on_failure=>false)
    end
  end
end
