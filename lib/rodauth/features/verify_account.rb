# frozen-string-literal: true

module Rodauth
  Feature.define(:verify_account, :VerifyAccount) do
    depends :login, :create_account, :email_base

    error_flash "Unable to verify account"
    error_flash "Unable to resend verify account email", 'verify_account_resend'
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
    redirect(:verify_account_email_sent){require_login_redirect}

    auth_value_method :no_matching_verify_account_key_message, "invalid verify account key"
    auth_value_method :attempt_to_create_unverified_account_notice_message, "The account you tried to create is currently awaiting verification"
    auth_value_method :attempt_to_login_to_unverified_account_notice_message, "The account you tried to login with is currently awaiting verification"
    auth_value_method :verify_account_email_subject, 'Verify Account'
    auth_value_method :verify_account_key_param, 'key'
    auth_value_method :verify_account_autologin?, true
    auth_value_method :verify_account_table, :account_verification_keys
    auth_value_method :verify_account_id_column, :id
    auth_value_method :verify_account_key_column, :key
    auth_value_method :verify_account_session_key, :verify_account_key
    auth_value_method :verify_account_set_password?, false

    auth_methods(
      :allow_resending_verify_account_email?,
      :create_verify_account_key,
      :create_verify_account_email,
      :get_verify_account_key,
      :remove_verify_account_key,
      :resend_verify_account_view,
      :send_verify_account_email,
      :verify_account,
      :verify_account_email_body,
      :verify_account_email_link,
      :verify_account_key_insert_hash,
      :verify_account_key_value
    )

    auth_private_methods(
      :account_from_verify_account_key
    )

    route(:verify_account_resend) do |r|
      verify_account_check_already_logged_in
      before_verify_account_resend_route

      r.get do
        resend_verify_account_view
      end

      r.post do
        if account_from_login(param(login_param)) && allow_resending_verify_account_email?
          before_verify_account_email_resend
          if verify_account_email_resend
            after_verify_account_email_resend
          end

          set_notice_flash verify_account_email_sent_notice_flash
        else
          set_redirect_error_status(no_matching_login_error_status)
          set_redirect_error_flash verify_account_resend_error_flash
        end
        
        redirect verify_account_email_sent_redirect
      end
    end

    route do |r|
      verify_account_check_already_logged_in
      before_verify_account_route

      r.get do
        if key = param_or_nil(verify_account_key_param)
          session[verify_account_session_key] = key
          redirect(r.path)
        end

        if key = session[verify_account_session_key]
          if account_from_verify_account_key(key)
            verify_account_view
          else
            session[verify_account_session_key] = nil
            set_redirect_error_flash no_matching_verify_account_key_message
            redirect require_login_redirect
          end
        end
      end

      r.post do
        key = session[verify_account_session_key] || param(verify_account_key_param)
        unless account_from_verify_account_key(key)
          set_redirect_error_status(invalid_key_error_status)
          set_redirect_error_flash verify_account_error_flash
          redirect verify_account_redirect
        end

        catch_error do
          if verify_account_set_password?
            password = param(password_param)

            if require_password_confirmation? && password != param(password_confirm_param)
              throw_error_status(unmatched_field_error_status, password_param, passwords_do_not_match_message)
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
            update_session
          end

          session[verify_account_session_key] = nil
          set_notice_flash verify_account_notice_flash
          redirect verify_account_redirect
        end

        set_error_flash verify_account_error_flash
        verify_account_view
      end
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
        send_verify_account_email
        true
      end
    end

    def create_account_notice_flash
      verify_account_email_sent_notice_flash
    end

    def new_account(login)
      if account_from_login(login) && allow_resending_verify_account_email?
        set_redirect_error_status(unopen_account_error_status)
        set_error_flash attempt_to_create_unverified_account_notice_message
        response.write resend_verify_account_view
        request.halt
      end
      super
    end

    def account_from_verify_account_key(key)
      @account = _account_from_verify_account_key(key)
    end

    def account_initial_status_value
      account_unverified_status_value
    end

    def send_verify_account_email
      create_verify_account_email.deliver!
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

    def login_form_footer
      super + verify_account_resend_link
    end

    def verify_account_resend_link
      "<p><a href=\"#{prefix}/#{verify_account_resend_route}\">Resend Verify Account Information</a></p>"
    end

    def create_account_set_password?
      return false if verify_account_set_password?
      super
    end

    private

    attr_reader :verify_account_key_value

    def before_login_attempt
      unless open_account?
        set_redirect_error_status(unopen_account_error_status)
        set_error_flash attempt_to_login_to_unverified_account_notice_message
        response.write resend_verify_account_view
        request.halt
      end
      super
    end

    def after_create_account
      setup_account_verification
      super
    end

    def setup_account_verification
      generate_verify_account_key_value
      create_verify_account_key
      send_verify_account_email
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

    def create_verify_account_email
      create_email(verify_account_email_subject, verify_account_email_body)
    end

    def verify_account_email_body
      render('verify-account-email')
    end

    def verify_account_ds(id=account_id)
      db[verify_account_table].where(verify_account_id_column=>id)
    end

    def _account_from_verify_account_key(token)
      account_from_key(token, account_unverified_status_value){|id| get_verify_account_key(id)}
    end
  end
end
