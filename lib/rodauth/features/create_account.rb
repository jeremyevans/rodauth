# frozen-string-literal: true

module Rodauth
  Feature.define(:create_account, :CreateAccount) do
    depends :login, :login_password_requirements_base

    notice_flash 'Your account has been created'
    error_flash "There was an error creating your account"
    loaded_templates %w'create-account login-field login-confirm-field password-field password-confirm-field'
    view 'create-account', 'Create Account'
    after
    before
    button 'Create Account'
    additional_form_tags
    redirect
    response

    auth_value_method :create_account_autologin?, true
    translatable_method :create_account_link_text, "Create a New Account"
    auth_value_method :create_account_set_password?, true

    auth_methods(
      :save_account,
      :set_new_account_password
    )

    auth_private_methods(
      :new_account
    )

    internal_request_method

    route do |r|
      check_already_logged_in
      before_create_account_route
      @password_field_autocomplete_value = 'new-password'

      r.get do
        create_account_view
      end

      r.post do
        login = login_param_value
        password = param(password_param)
        new_account(login)

        catch_error do
          if require_login_confirmation? && !login_confirmation_matches?(login, param(login_confirm_param))
            throw_error_reason(:logins_do_not_match, unmatched_field_error_status, login_param, logins_do_not_match_message)
          end

          unless login_meets_requirements?(login)
            throw_error_status(invalid_field_error_status, login_param, login_does_not_meet_requirements_message)
          end

          if create_account_set_password?
            if require_password_confirmation? && password != param(password_confirm_param)
              throw_error_reason(:passwords_do_not_match, unmatched_field_error_status, password_param, passwords_do_not_match_message)
            end

            unless password_meets_requirements?(password)
              throw_error_reason(:password_does_not_meet_requirements, invalid_field_error_status, password_param, password_does_not_meet_requirements_message)
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
              autologin_session('create_account')
            end
            create_account_response
          end
        end

        set_error_flash create_account_error_flash
        create_account_view
      end
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
        set_login_requirement_error_message(:already_an_account_with_this_login, already_an_account_with_this_login_message)
      end

      if id
        account[account_id_column] ||= id
      end

      id && !raised
    end

    private

    def _login_form_footer_links
      super << [10, create_account_path, create_account_link_text]
    end

    def _new_account(login)
      acc = {login_column=>login}
      unless skip_status_checks?
        acc[account_status_column] = account_initial_status_value
      end
      acc
    end
  end
end
