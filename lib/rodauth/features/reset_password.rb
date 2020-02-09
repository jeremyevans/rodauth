# frozen-string-literal: true

module Rodauth
  Feature.define(:reset_password, :ResetPassword) do
    depends :login, :email_base, :login_password_requirements_base

    def_deprecated_alias :no_matching_reset_password_key_error_flash, :no_matching_reset_password_key_message

    notice_flash "Your password has been reset"
    notice_flash "An email has been sent to you with a link to reset the password for your account", 'reset_password_email_sent'
    error_flash "There was an error resetting your password"
    error_flash "There was an error requesting a password reset", 'reset_password_request'
    error_flash "An email has recently been sent to you with a link to reset your password", 'reset_password_email_recently_sent'
    error_flash "There was an error resetting your password: invalid or expired password reset key", 'no_matching_reset_password_key'
    loaded_templates %w'reset-password-request reset-password password-field password-confirm-field reset-password-email'
    view 'reset-password', 'Reset Password'
    view 'reset-password-request', 'Request Password Reset', 'reset_password_request'
    additional_form_tags
    additional_form_tags 'reset_password_request'
    before 
    before 'reset_password_request'
    after
    after 'reset_password_request'
    button 'Reset Password'
    button 'Request Password Reset', 'reset_password_request'
    redirect
    redirect(:reset_password_email_sent){default_post_email_redirect}
    redirect(:reset_password_email_recently_sent){default_post_email_redirect}
    
    auth_value_method :reset_password_deadline_column, :deadline
    auth_value_method :reset_password_deadline_interval, {:days=>1}
    auth_value_method :reset_password_email_subject, 'Reset Password'
    auth_value_method :reset_password_key_param, 'key'
    auth_value_method :reset_password_autologin?, false
    auth_value_method :reset_password_table, :account_password_reset_keys
    auth_value_method :reset_password_id_column, :id
    auth_value_method :reset_password_key_column, :key
    auth_value_method :reset_password_email_last_sent_column, nil
    auth_value_method :reset_password_explanatory_text, "<p>If you have forgotten your password, you can request a password reset:</p>"
    auth_value_method :reset_password_skip_resend_email_within, 300
    session_key :reset_password_session_key, :reset_password_key

    auth_value_methods :reset_password_request_link

    auth_methods(
      :create_reset_password_key,
      :create_reset_password_email,
      :get_reset_password_key,
      :get_reset_password_email_last_sent,
      :login_failed_reset_password_request_form,
      :remove_reset_password_key,
      :reset_password_email_body,
      :reset_password_email_link,
      :reset_password_key_insert_hash,
      :reset_password_key_value,
      :send_reset_password_email,
      :set_reset_password_email_last_sent
    )
    auth_private_methods(
      :account_from_reset_password_key
    )

    route(:reset_password_request) do |r|
      check_already_logged_in
      before_reset_password_request_route

      r.get do
        reset_password_request_view
      end

      r.post do
        if account_from_login(param(login_param)) && open_account?
          if reset_password_email_recently_sent?
            set_redirect_error_flash reset_password_email_recently_sent_error_flash
            redirect reset_password_email_recently_sent_redirect
          end

          generate_reset_password_key_value
          transaction do
            before_reset_password_request
            create_reset_password_key
            send_reset_password_email
            after_reset_password_request
          end

          set_notice_flash reset_password_email_sent_notice_flash
        else
          set_redirect_error_status(no_matching_login_error_status)
          set_redirect_error_flash reset_password_request_error_flash
        end

        redirect reset_password_email_sent_redirect
      end
    end

    route do |r|
      check_already_logged_in
      before_reset_password_route

      r.get do
        if key = param_or_nil(reset_password_key_param)
          session[reset_password_session_key] = key
          redirect(r.path)
        end

        if key = session[reset_password_session_key]
          if account_from_reset_password_key(key)
            reset_password_view
          else
            session[reset_password_session_key] = nil
            set_redirect_error_flash no_matching_reset_password_key_error_flash
            redirect require_login_redirect
          end
        end
      end

      r.post do
        key = session[reset_password_session_key] || param(reset_password_key_param)
        unless account_from_reset_password_key(key)
          set_redirect_error_status(invalid_key_error_status)
          set_redirect_error_flash reset_password_error_flash
          redirect reset_password_email_sent_redirect
        end

        password = param(password_param)
        catch_error do
          if password_match?(password) 
            throw_error_status(invalid_field_error_status, password_param, same_as_existing_password_message)
          end

          if require_password_confirmation? && password != param(password_confirm_param)
            throw_error_status(unmatched_field_error_status, password_param, passwords_do_not_match_message)
          end

          unless password_meets_requirements?(password)
            throw_error_status(invalid_field_error_status, password_param, password_does_not_meet_requirements_message)
          end

          transaction do
            before_reset_password
            set_password(password)
            remove_reset_password_key
            after_reset_password
          end

          if reset_password_autologin?
            update_session
          end

          session[reset_password_session_key] = nil
          set_notice_flash reset_password_notice_flash
          redirect reset_password_redirect
        end

        set_error_flash reset_password_error_flash
        reset_password_view
      end
    end

    def create_reset_password_key
      transaction do
        if reset_password_key_value = get_password_reset_key(account_id)
          set_reset_password_email_last_sent
          @reset_password_key_value = reset_password_key_value
        elsif e = raised_uniqueness_violation{password_reset_ds.insert(reset_password_key_insert_hash)}
          # If inserting into the reset password table causes a violation, we can pull the 
          # existing reset password key from the table, or reraise.
          raise e unless @reset_password_key_value = get_password_reset_key(account_id)
        end
      end
    end

    def remove_reset_password_key
      password_reset_ds.delete
    end

    def account_from_reset_password_key(key)
      @account = _account_from_reset_password_key(key)
    end

    def send_reset_password_email
      send_email(create_reset_password_email)
    end

    def reset_password_email_link
      token_link(reset_password_route, reset_password_key_param, reset_password_key_value)
    end

    def get_password_reset_key(id)
      ds = password_reset_ds(id)
      ds.where(Sequel::CURRENT_TIMESTAMP > reset_password_deadline_column).delete
      ds.get(reset_password_key_column)
    end

    def login_form_footer
      super + reset_password_request_link
    end

    def reset_password_request_link
      "<p><a href=\"#{prefix}/#{reset_password_request_route}\">Forgot Password?</a></p>"
    end

    def set_reset_password_email_last_sent
       password_reset_ds.update(reset_password_email_last_sent_column=>Sequel::CURRENT_TIMESTAMP) if reset_password_email_last_sent_column
    end

    def get_reset_password_email_last_sent
      if column = reset_password_email_last_sent_column
        if ts = password_reset_ds.get(column)
          convert_timestamp(ts)
        end
      end
    end

    private

    def reset_password_email_recently_sent?
      (email_last_sent = get_reset_password_email_last_sent) && (Time.now - email_last_sent < reset_password_skip_resend_email_within)
    end

    attr_reader :reset_password_key_value

    def after_login_failure
      unless only_json?
        @login_form_header = login_failed_reset_password_request_form
      end
      super
    end

    def after_close_account
      remove_reset_password_key
      super if defined?(super)
    end

    def generate_reset_password_key_value
      @reset_password_key_value = random_key
    end

    def create_reset_password_email
      create_email(reset_password_email_subject, reset_password_email_body)
    end

    def login_failed_reset_password_request_form
      render("reset-password-request")
    end

    def reset_password_email_body
      render('reset-password-email')
    end

    def use_date_arithmetic?
      super || db.database_type == :mysql
    end

    def reset_password_key_insert_hash
      hash = {reset_password_id_column=>account_id, reset_password_key_column=>reset_password_key_value}
      set_deadline_value(hash, reset_password_deadline_column, reset_password_deadline_interval)
      hash
    end

    def password_reset_ds(id=account_id)
      db[reset_password_table].where(reset_password_id_column=>id)
    end

    def _account_from_reset_password_key(token)
      account_from_key(token, account_open_status_value){|id| get_password_reset_key(id)}
    end
  end
end
