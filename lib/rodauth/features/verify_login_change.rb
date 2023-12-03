# frozen-string-literal: true

module Rodauth
  Feature.define(:verify_login_change, :VerifyLoginChange) do
    depends :change_login, :email_base

    error_flash "Unable to verify login change"
    error_flash "Unable to change login as there is already an account with the new login", 'verify_login_change_duplicate_account'
    error_flash "There was an error verifying your login change: invalid verify login change key", 'no_matching_verify_login_change_key'
    notice_flash "Your login change has been verified"
    notice_flash "An email has been sent to you with a link to verify your login change", 'change_login_needs_verification'
    loaded_templates %w'verify-login-change verify-login-change-email'
    view 'verify-login-change', 'Verify Login Change'
    additional_form_tags
    after
    after 'verify_login_change_email'
    before
    before 'verify_login_change_email'
    button 'Verify Login Change'
    redirect
    response
    redirect(:verify_login_change_duplicate_account){require_login_redirect}

    auth_value_method :verify_login_change_autologin?, false
    auth_value_method :verify_login_change_deadline_column, :deadline
    auth_value_method :verify_login_change_deadline_interval, {:days=>1}.freeze
    translatable_method :verify_login_change_email_subject, 'Verify Login Change'
    auth_value_method :verify_login_change_id_column, :id
    auth_value_method :verify_login_change_key_column, :key
    auth_value_method :verify_login_change_key_param, 'key'
    auth_value_method :verify_login_change_login_column, :login
    session_key :verify_login_change_session_key, :verify_login_change_key
    auth_value_method :verify_login_change_table, :account_login_change_keys

    auth_methods(
      :create_verify_login_change_email,
      :create_verify_login_change_key,
      :get_verify_login_change_login_and_key,
      :remove_verify_login_change_key,
      :send_verify_login_change_email,
      :verify_login_change,
      :verify_login_change_email_body,
      :verify_login_change_email_link,
      :verify_login_change_key_insert_hash,
      :verify_login_change_key_value,
      :verify_login_change_new_login,
      :verify_login_change_old_login
    )

    auth_private_methods(
      :account_from_verify_login_change_key
    )

    internal_request_method

    route do |r|
      before_verify_login_change_route

      r.get do
        if key = param_or_nil(verify_login_change_key_param)
          set_session_value(verify_login_change_session_key, key)
          redirect(r.path)
        end

        if (key = session[verify_login_change_session_key]) && account_from_verify_login_change_key(key)
          verify_login_change_view
        else
          remove_session_value(verify_login_change_session_key)
          set_redirect_error_flash no_matching_verify_login_change_key_error_flash
          redirect require_login_redirect
        end
      end

      r.post do
        key = session[verify_login_change_session_key] || param(verify_login_change_key_param)
        unless account_from_verify_login_change_key(key)
          set_redirect_error_status(invalid_key_error_status)
          set_error_reason :invalid_verify_login_change_key
          set_redirect_error_flash verify_login_change_error_flash
          redirect verify_login_change_redirect
        end

        transaction do
          before_verify_login_change
          unless verify_login_change
            set_redirect_error_status(invalid_key_error_status)
            set_error_reason :already_an_account_with_this_login
            set_redirect_error_flash verify_login_change_duplicate_account_error_flash
            redirect verify_login_change_duplicate_account_redirect
          end
          remove_verify_login_change_key
          after_verify_login_change
        end

        if verify_login_change_autologin?
          autologin_session('verify_login_change')
        end

        remove_session_value(verify_login_change_session_key)
        verify_login_change_response
      end
    end

    def require_login_confirmation?
      false
    end

    def remove_verify_login_change_key
      verify_login_change_ds.delete
    end

    def verify_login_change
      unless res = _update_login(verify_login_change_new_login)
        remove_verify_login_change_key
      end

      res
    end

    def account_from_verify_login_change_key(key)
      @account = _account_from_verify_login_change_key(key)
    end

    def send_verify_login_change_email(login)
      send_email(create_verify_login_change_email(login))
    end

    def verify_login_change_email_link
      token_link(verify_login_change_route, verify_login_change_key_param, verify_login_change_key_value)
    end

    def get_verify_login_change_login_and_key(id)
      verify_login_change_ds(id).get([verify_login_change_login_column, verify_login_change_key_column])
    end

    def change_login_notice_flash
      change_login_needs_verification_notice_flash
    end

    def verify_login_change_old_login
      account_ds.get(login_column)
    end

    attr_reader :verify_login_change_key_value
    attr_reader :verify_login_change_new_login

    private

    def after_close_account
      remove_verify_login_change_key
      super if defined?(super)
    end

    def update_login(login)
      if _account_from_login(login)
        set_login_requirement_error_message(:already_an_account_with_this_login, already_an_account_with_this_login_message)
        return false
      end

      transaction do
        before_verify_login_change_email
        generate_verify_login_change_key_value
        @verify_login_change_new_login = login
        create_verify_login_change_key(login)
        send_verify_login_change_email(login)
        after_verify_login_change_email
      end

      true
    end

    def generate_verify_login_change_key_value
      @verify_login_change_key_value = random_key
    end

    def create_verify_login_change_key(login)
      ds = verify_login_change_ds
      transaction do
        ds.where((Sequel::CURRENT_TIMESTAMP > verify_login_change_deadline_column) | ~Sequel.expr(verify_login_change_login_column=>login)).delete
        if e = raised_uniqueness_violation{ds.insert(verify_login_change_key_insert_hash(login))}
          old_login, key = get_verify_login_change_login_and_key(account_id)
          # If inserting into the verify login change table causes a violation, we can pull the 
          # key from the verify login change table if the logins match, or reraise.
          @verify_login_change_key_value = if old_login.downcase == login.downcase
            key
          end
          raise e unless @verify_login_change_key_value
        end
      end
    end

    def verify_login_change_key_insert_hash(login)
      hash = {verify_login_change_id_column=>account_id, verify_login_change_key_column=>verify_login_change_key_value, verify_login_change_login_column=>login}
      set_deadline_value(hash, verify_login_change_deadline_column, verify_login_change_deadline_interval)
      hash
    end

    def create_verify_login_change_email(login)
      create_email_to(login, verify_login_change_email_subject, verify_login_change_email_body)
    end

    def verify_login_change_email_body
      render('verify-login-change-email')
    end

    def verify_login_change_ds(id=account_id)
      db[verify_login_change_table].where(verify_login_change_id_column=>id)
    end

    def _account_from_verify_login_change_key(token)
      account_from_key(token) do |id|
        @verify_login_change_new_login, key = get_verify_login_change_login_and_key(id)
        key
      end
    end
  end
end
