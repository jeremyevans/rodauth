# frozen-string-literal: true

module Rodauth
  Feature.define(:create_account, :CreateAccount) do
    depends :login_password_requirements_base

    depends :login
    notice_flash 'Your account has been created'
    error_flash "There was an error creating your account"
    loaded_templates %w'create-account login-field login-confirm-field password-field password-confirm-field'
    view 'create-account', 'Create Account'
    after
    before
    button 'Create Account'
    additional_form_tags
    redirect

    auth_value_method :create_account_autologin?, true
    auth_value_method :create_account_set_password?, true

    auth_value_methods :create_account_link

    auth_methods(
      :save_account,
      :set_new_account_password
    )

    auth_private_methods(
      :new_account
    )

    route do |r|
      check_already_logged_in
      before_create_account_route

      r.get do
        create_account_view
      end

      r.post do
        login = param(login_param)
        password = param(password_param)
        new_account(login)

        catch_error do
          if require_login_confirmation? && login != param(login_confirm_param)
            throw_error_status(unmatched_field_error_status, login_param, logins_do_not_match_message)
          end

          unless login_meets_requirements?(login)
            throw_error_status(invalid_field_error_status, login_param, login_does_not_meet_requirements_message)
          end

          if create_account_set_password?
            if require_password_confirmation? && password != param(password_confirm_param)
              throw_error_status(unmatched_field_error_status, password_param, passwords_do_not_match_message)
            end

            unless password_meets_requirements?(password)
              throw_error_status(invalid_field_error_status, password_param, password_does_not_meet_requirements_message)
            end

            if account_password_hash_column
              set_new_account_password(password)
            end
          end

          transaction do
            before_create_account
            unless save_account
              throw_error_status(invalid_field_error_status, login_param, login_does_not_meet_requirements_message)
            end

            if create_account_set_password? && !account_password_hash_column
              set_password(password)
            end
            after_create_account
            if create_account_autologin?
              update_session
            end
            set_notice_flash create_account_notice_flash
            redirect create_account_redirect
          end
        end

        set_error_flash create_account_error_flash
        create_account_view
      end
    end

    def create_account_link
      "<p><a href=\"#{prefix}/#{create_account_route}\">Create a New Account</a></p>"
    end

    def login_form_footer
      super + create_account_link
    end

    def set_new_account_password(password)
      account[account_password_hash_column] = password_hash(password)
    end

    def new_account(login)
      @account = _new_account(login)
    end
    
    def save_account
      id = nil
      raised = raises_uniqueness_violation?{id = db[accounts_table].insert(account)}

      if raised
        @login_requirement_message = 'already an account with this login'
      end

      if id
        account[account_id_column] = id
      end

      id && !raised
    end

    private

    def _new_account(login)
      acc = {login_column=>login}
      unless skip_status_checks?
        acc[account_status_column] = account_initial_status_value
      end
      acc
    end
  end
end
