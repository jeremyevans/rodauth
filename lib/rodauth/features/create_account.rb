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

    auth_value_method :create_account_autologin?, false
    auth_value_methods :create_account_link
    auth_methods(
      :new_account,
      :save_account,
      :set_new_account_password
    )

    get_block do |r, auth|
      auth.create_account_view
    end

    post_block do |r, auth|
      login = auth.param(auth.login_param)
      password = auth.param(auth.password_param)
      auth._new_account(login)

      if auth.account_password_hash_column
        auth.set_new_account_password(auth.param(auth.password_param))
      end

      if login == auth.param(auth.login_confirm_param)
        if auth.login_meets_requirements?(login)
          if password == auth.param(auth.password_confirm_param)
            if auth.password_meets_requirements?(password)
              auth.transaction do
                if auth.save_account
                  unless auth.account_password_hash_column
                    auth.set_password(password)
                  end
                  auth._after_create_account
                  if auth.create_account_autologin?
                    auth.update_session
                  end
                  auth.set_notice_flash auth.create_account_notice_flash
                  r.redirect(auth.create_account_redirect)
                else
                  @login_error = auth.login_does_not_meet_requirements_message
                end
              end
            else
              @password_error = auth.password_does_not_meet_requirements_message
            end
          else
            @password_error = auth.passwords_do_not_match_message
          end
        else
          @login_error = auth.login_does_not_meet_requirements_message
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

    def new_account(login)
      @account = {login_column=>login}
      unless skip_status_checks?
        account[account_status_id] = account_initial_status_value
      end
      @account
    end

    def set_new_account_password(password)
      account[account_password_hash_column] = password_hash(password)
    end
    
    def _new_account(login)
      @account = new_account(login)
    end

    def save_account
      id = nil
      raised = raises_uniqueness_violation?{id = db[accounts_table].insert(account)}

      if raised
        @login_requirement_message = 'already an account with this login'
      end

      if id
        account[account_id] = id
      end

      id && !raised
    end
  end
end
