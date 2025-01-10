# frozen-string-literal: true

module Rodauth
  Feature.define(:verify_account, :VerifyAccount) do
    depends :login, :create_account, :email_base

    error_flash "Unable to verify account"
    error_flash "Unable to resend verify account email", 'verify_account_resend'
    error_flash "An email has recently been sent to you with a link to verify your account", 'verify_account_email_recently_sent'
    error_flash "There was an error verifying your account: invalid verify account key", 'no_matching_verify_account_key'
    error_flash "The account you tried to create is currently awaiting verification", 'attempt_to_create_unverified_account'
    error_flash "The account you tried to login with is currently awaiting verification", 'attempt_to_login_to_unverified_account'
    notice_flash "Your account has been verified"
    notice_flash "An email has been sent to you with a link to verify your account", 'verify_account_email_sent'
    loaded_templates %w'verify-account verify-account-resend verify-account-email'
    view 'verify-account', 'Verify Account'
    view 'verify-account-resend', 'Resend Verification Email', 'resend_verify_account'
    additional_form_tags
    additional_form_tags 'verify_account_resend'
    after
    after 'verify_account_email_resend'
    before
    before 'verify_account_email_resend'
    button 'Verify Account'
    button 'Send Verification Email Again', 'verify_account_resend'
    redirect
    response
    response :verify_account_email_sent
    redirect(:verify_account_email_sent){default_post_email_redirect}
    redirect(:verify_account_email_recently_sent){default_post_email_redirect}
    email :verify_account, 'Verify Account'

    auth_value_method :verify_account_key_param, 'key'
    auth_value_method :verify_account_autologin?, true
    auth_value_method :verify_account_table, :account_verification_keys
    auth_value_method :verify_account_id_column, :id
    auth_value_method :verify_account_email_last_sent_column, :email_last_sent
    auth_value_method :verify_account_skip_resend_email_within, 300
    auth_value_method :verify_account_key_column, :key
    translatable_method :verify_account_resend_explanatory_text, "<p>If you no longer have the email to verify the account, you can request that it be resent to you:</p>"
    translatable_method :verify_account_resend_link_text, "Resend Verify Account Information"
    session_key :verify_account_session_key, :verify_account_key
    auth_value_method :verify_account_set_password?, true

    auth_methods(
      :allow_resending_verify_account_email?,
      :create_verify_account_key,
      :get_verify_account_key,
      :get_verify_account_email_last_sent,
      :remove_verify_account_key,
      :set_verify_account_email_last_sent,
      :verify_account,
      :verify_account_email_link,
      :verify_account_key_insert_hash,
      :verify_account_key_value
    )

    auth_private_methods(
      :account_from_verify_account_key
    )

    internal_request_method(:verify_account_resend)
    internal_request_method

    route(:verify_account_resend) do |r|
      verify_account_check_already_logged_in
      before_verify_account_resend_route

      r.get do
        resend_verify_account_view
      end

      r.post do
        if account_from_login(login_param_value) && allow_resending_verify_account_email?
          if verify_account_email_recently_sent?
            set_redirect_error_flash verify_account_email_recently_sent_error_flash
            redirect verify_account_email_recently_sent_redirect
          end

          before_verify_account_email_resend
          if verify_account_email_resend
            after_verify_account_email_resend
            verify_account_email_sent_response
          end
        end

        set_redirect_error_status(no_matching_login_error_status)
        set_error_reason :no_matching_login
        set_redirect_error_flash verify_account_resend_error_flash
        redirect verify_account_email_sent_redirect
      end
    end

    route do |r|
      verify_account_check_already_logged_in
      before_verify_account_route
      @password_field_autocomplete_value = 'new-password'

      r.get do
        if key = param_or_nil(verify_account_key_param)
          set_session_value(verify_account_session_key, key)
          redirect(r.path)
        end

        if (key = session[verify_account_session_key]) && account_from_verify_account_key(key)
          verify_account_view
        else
          remove_session_value(verify_account_session_key)
          set_redirect_error_flash no_matching_verify_account_key_error_flash
          redirect require_login_redirect
        end
      end

      r.post do
        key = session[verify_account_session_key] || param(verify_account_key_param)
        unless account_from_verify_account_key(key)
          set_redirect_error_status(invalid_key_error_status)
          set_error_reason :invalid_verify_account_key
          set_redirect_error_flash verify_account_error_flash
          redirect verify_account_redirect
        end

        catch_error do
          if verify_account_set_password?
            password = param(password_param)

            if require_password_confirmation? && password != param(password_confirm_param)
              throw_error_reason(:passwords_do_not_match, unmatched_field_error_status, password_param, passwords_do_not_match_message)
            end

            unless password_meets_requirements?(password)
              throw_error_status(invalid_field_error_status, password_param, password_does_not_meet_requirements_message)
            end
          end

          transaction do
            before_verify_account
            verify_account
            if verify_account_set_password?
              set_password(password)
            end
            remove_verify_account_key
            after_verify_account
          end

          if verify_account_autologin?
            autologin_session('verify_account')
          end

          remove_session_value(verify_account_session_key)
          verify_account_response
        end

        set_error_flash verify_account_error_flash
        verify_account_view
      end
    end

    def require_login_confirmation?
      false
    end

    def allow_resending_verify_account_email?
      account[account_status_column] == account_unverified_status_value
    end

    def remove_verify_account_key
      verify_account_ds.delete
    end

    def verify_account
      update_account(account_status_column=>account_open_status_value) == 1
    end

    def verify_account_email_resend
      if @verify_account_key_value = get_verify_account_key(account_id)
        set_verify_account_email_last_sent
        send_verify_account_email
        true
      end
    end

    def create_account_notice_flash
      verify_account_email_sent_notice_flash
    end

    def new_account(login)
      if account_from_login(login) && allow_resending_verify_account_email?
        set_response_error_reason_status(:already_an_unverified_account_with_this_login, unopen_account_error_status)
        set_error_flash attempt_to_create_unverified_account_error_flash
        return_response resend_verify_account_view
      end
      super
    end

    def account_from_verify_account_key(key)
      @account = _account_from_verify_account_key(key)
    end

    def account_initial_status_value
      account_unverified_status_value
    end

    def verify_account_email_link
      token_link(verify_account_route, verify_account_key_param, verify_account_key_value)
    end

    def get_verify_account_key(id)
      verify_account_ds(id).get(verify_account_key_column)
    end

    def skip_status_checks?
      false
    end

    def create_account_autologin?
      false
    end

    def create_account_set_password?
      return false if verify_account_set_password?
      super
    end

    def set_verify_account_email_last_sent
       verify_account_ds.update(verify_account_email_last_sent_column=>Sequel::CURRENT_TIMESTAMP) if verify_account_email_last_sent_column
    end

    def get_verify_account_email_last_sent
      if column = verify_account_email_last_sent_column
        if ts = verify_account_ds.get(column)
          convert_timestamp(ts)
        end
      end
    end

    def setup_account_verification
      generate_verify_account_key_value
      create_verify_account_key
      send_verify_account_email
    end

    def verify_account_email_recently_sent?
      account && (email_last_sent = get_verify_account_email_last_sent) && (Time.now - email_last_sent < verify_account_skip_resend_email_within)
    end

    private

    def _login_form_footer_links
      links = super
      if !param_or_nil(login_param) || ((account || account_from_login(login_param_value)) && allow_resending_verify_account_email?)
        links << [30, verify_account_resend_path, verify_account_resend_link_text]
      end
      links
    end

    attr_reader :verify_account_key_value

    def before_login_attempt
      unless open_account?
        set_response_error_reason_status(:unverified_account, unopen_account_error_status)
        set_error_flash attempt_to_login_to_unverified_account_error_flash
        return_response resend_verify_account_view
      end
      super
    end

    def after_create_account
      setup_account_verification
      super
    end

    def verify_account_check_already_logged_in
      check_already_logged_in
    end

    def generate_verify_account_key_value
      @verify_account_key_value = random_key
    end

    def create_verify_account_key
      ds = verify_account_ds
      transaction do
        if ds.empty?
          if e = raised_uniqueness_violation{ds.insert(verify_account_key_insert_hash)}
            # If inserting into the verify account table causes a violation, we can pull the 
            # key from the verify account table, or reraise.
            raise e unless @verify_account_key_value = get_verify_account_key(account_id)
          end
        end
      end
    end

    def verify_account_key_insert_hash
      {verify_account_id_column=>account_id, verify_account_key_column=>verify_account_key_value}
    end

    def verify_account_ds(id=account_id)
      db[verify_account_table].where(verify_account_id_column=>id)
    end

    def _account_from_verify_account_key(token)
      account_from_key(token, account_unverified_status_value){|id| get_verify_account_key(id)}
    end
  end
end
