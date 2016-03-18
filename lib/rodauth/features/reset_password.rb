module Rodauth
  ResetPassword = Feature.define(:reset_password) do
    depends :login
    route 'reset-password'
    notice_flash "Your password has been reset"
    error_flash "There was an error resetting your password"
    view 'reset-password', 'Reset Password'
    additional_form_tags
    additional_form_tags 'reset_password_request'
    after
    after 'reset_password_request'
    button 'Reset Password'
    button 'Request Password Reset', 'reset_password_request'
    redirect
    redirect :reset_password_email_sent
    
    auth_value_method :reset_password_deadline_column, :deadline
    auth_value_method :reset_password_deadline_interval, {:days=>1}
    auth_value_method :reset_password_email_sent_notice_message, "An email has been sent to you with a link to reset the password for your account"
    auth_value_method :no_matching_reset_password_key_message, "invalid password reset key"
    auth_value_method :reset_password_email_subject, 'Reset Password'
    auth_value_method :reset_password_key_param, 'key'
    auth_value_method :reset_password_autologin?, false
    auth_value_method :reset_password_table, :account_password_reset_keys
    auth_value_method :reset_password_id_column, :id
    auth_value_method :reset_password_key_column, :key

    auth_value_methods :reset_password_email_sent_redirect

    auth_methods(
      :account_from_reset_password_key,
      :create_reset_password_key,
      :create_reset_password_email,
      :remove_reset_password_key,
      :reset_password_email_body,
      :reset_password_email_link,
      :reset_password_key_insert_hash,
      :reset_password_key_value,
      :send_reset_password_email
    )

    get_block do |r, auth|
      if key = r[auth.reset_password_key_param]
        if auth._account_from_reset_password_key(key)
          auth.reset_password_view
        else
          auth.set_redirect_error_flash auth.no_matching_reset_password_key_message
          r.redirect auth.require_login_redirect
        end
      end
    end

    post_block do |r, auth|
      if login = r[auth.login_param]
        if auth._account_from_login(login.to_s) && auth.open_account?
          auth.generate_reset_password_key_value
          auth.transaction do
            auth.create_reset_password_key
            auth.send_reset_password_email
            auth.after_reset_password_request
          end
          auth.set_notice_flash auth.reset_password_email_sent_notice_message
          r.redirect auth.reset_password_email_sent_redirect
        end
      elsif key = r[auth.reset_password_key_param]
        if auth._account_from_reset_password_key(key)
          if r[auth.password_param] == r[auth.password_confirm_param]
            if auth.password_meets_requirements?(r[auth.password_param].to_s)
              auth.transaction do
                auth.set_password(r[auth.password_param])
                auth.remove_reset_password_key
                auth.after_reset_password
              end
              if auth.reset_password_autologin?
                auth.update_session
              end
              auth.set_notice_flash auth.reset_password_notice_flash
              r.redirect(auth.reset_password_redirect)
            else
              @password_error = auth.password_does_not_meet_requirements_message
            end
          else
            @password_error = auth.passwords_do_not_match_message
          end
          auth.set_error_flash auth.reset_password_error_flash
          auth.reset_password_view
        end
      end
    end

    def after_login_failure
      super
      scope.instance_variable_set(:@login_form_header, render("reset-password-request"))
    end

    def generate_reset_password_key_value
      @reset_password_key_value = random_key
    end

    def create_reset_password_key
      ds = db[reset_password_table].where(reset_password_id_column=>account_id_value)
      transaction do
        ds.where(Sequel::CURRENT_TIMESTAMP > reset_password_deadline_column).delete
        if ds.empty?
          ds.insert(reset_password_key_insert_hash)
        end
      end
    end

    def reset_password_key_insert_hash
      hash = {reset_password_id_column=>account_id_value, reset_password_key_column=>reset_password_key_value}
      set_deadline_value(hash, reset_password_deadline_column, reset_password_deadline_interval)
      hash
    end

    def remove_reset_password_key
      db[reset_password_table].where(reset_password_id_column=>account_id_value).delete
    end

    def _account_from_reset_password_key(key)
      @account = account_from_reset_password_key(key)
    end

    def account_from_reset_password_key(key)
      id, key = key.split('_', 2)
      return unless id && key

      id_column = reset_password_id_column
      id = id.to_i

      return unless actual = db[reset_password_table].
        where(id_column=>id).
        get(reset_password_key_column)

      return unless timing_safe_eql?(key, actual)

      ds = account_model.where(account_id=>id)
      ds = ds.where(account_status_id=>account_open_status_value) unless skip_status_checks?
      ds.first
    end

    attr_reader :reset_password_key_value

    def create_reset_password_email
      create_email(reset_password_email_subject, reset_password_email_body)
    end

    def send_reset_password_email
      create_reset_password_email.deliver!
    end

    def reset_password_email_body
      render('reset-password-email')
    end

    def reset_password_email_link
      "#{request.base_url}#{prefix}/#{reset_password_route}?#{reset_password_key_param}=#{account_id_value}_#{reset_password_key_value}"
    end

    def after_close_account
      super
      db[reset_password_table].where(reset_password_id_column=>account_id_value).delete
    end

    def require_mail?
      true
    end

    def use_date_arithmetic?
      db.database_type == :mysql
    end
  end
end
