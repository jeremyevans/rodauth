# frozen-string-literal: true

module Rodauth
  Feature.define(:login_password_requirements_base, :LoginPasswordRequirementsBase) do
    translatable_method :already_an_account_with_this_login_message, 'already an account with this login'
    auth_value_method :login_confirm_param, 'login-confirm'
    auth_value_method :login_email_regexp, /\A[^,;@ \r\n]+@[^,@; \r\n]+\.[^,@; \r\n]+\z/
    auth_value_method :login_minimum_length, 3
    auth_value_method :login_maximum_length, 255
    auth_value_method :login_maximum_bytes, 255
    translatable_method :login_not_valid_email_message, 'not a valid email address'
    translatable_method :logins_do_not_match_message, 'logins do not match'
    auth_value_method :password_confirm_param, 'password-confirm'
    auth_value_method :password_minimum_length, 6
    auth_value_method :password_maximum_bytes, nil
    auth_value_method :password_maximum_length, nil
    translatable_method :passwords_do_not_match_message, 'passwords do not match'
    auth_value_method :require_email_address_logins?, true
    auth_value_method :require_login_confirmation?, true
    auth_value_method :require_password_confirmation?, true
    translatable_method :same_as_existing_password_message, "invalid password, same as current password"
    translatable_method :contains_null_byte_message, 'contains null byte'

    auth_value_methods(
      :login_confirm_label,
      :login_does_not_meet_requirements_message,
      :login_too_long_message,
      :login_too_many_bytes_message,
      :login_too_short_message,
      :password_confirm_label,
      :password_does_not_meet_requirements_message,
      :password_hash_cost,
      :password_too_long_message,
      :password_too_many_bytes_message,
      :password_too_short_message
    )

    auth_methods(
      :login_confirmation_matches?,
      :login_meets_requirements?,
      :login_valid_email?,
      :password_hash,
      :password_meets_requirements?,
      :set_password
    )

    def login_confirm_label
      "Confirm #{login_label}"
    end

    def password_confirm_label
      "Confirm #{password_label}"
    end

    def login_meets_requirements?(login)
      login_meets_length_requirements?(login) && \
        login_meets_email_requirements?(login)
    end

    def password_meets_requirements?(password)
      password_meets_length_requirements?(password) && \
        password_does_not_contain_null_byte?(password)
    end

    def set_password(password)
      hash = password_hash(password)
      if account_password_hash_column
        update_account(account_password_hash_column=>hash)
      elsif password_hash_ds.update(password_hash_column=>hash) == 0
        # This shouldn't raise a uniqueness error, as the update should only fail for a new user,
        # and an existing user should always have a valid password hash row.  If this does
        # fail, retrying it will cause problems, it will override a concurrently running update
        # with potentially a different password.
        db[password_hash_table].insert(password_hash_id_column=>account_id, password_hash_column=>hash)
      end
      hash
    end

    def password_hash(password)
      BCrypt::Password.create(password, :cost=>password_hash_cost)
    end

    private
    
    attr_reader :login_requirement_message
    attr_reader :password_requirement_message

    def password_does_not_meet_requirements_message
      "invalid password, does not meet requirements#{" (#{password_requirement_message})" if password_requirement_message}"
    end

    def password_too_long_message
      "maximum #{password_maximum_length} characters"
    end
    
    def password_too_many_bytes_message
      "maximum #{password_maximum_bytes} bytes"
    end
    
    def password_too_short_message
      "minimum #{password_minimum_length} characters"
    end
    
    def set_password_requirement_error_message(reason, message)
      set_error_reason(reason)
      @password_requirement_message = message
    end

    def login_does_not_meet_requirements_message
      "invalid login#{", #{login_requirement_message}" if login_requirement_message}"
    end

    def login_too_long_message
      "maximum #{login_maximum_length} characters"
    end

    def login_too_many_bytes_message
      "maximum #{login_maximum_bytes} bytes"
    end

    def login_too_short_message
      "minimum #{login_minimum_length} characters"
    end
    
    def set_login_requirement_error_message(reason, message)
      set_error_reason(reason)
      @login_requirement_message = message
    end

    if RUBY_VERSION >= '2.4'
      def login_confirmation_matches?(login, login_confirmation)
        login.casecmp?(login_confirmation)
      end
    # :nocov:
    else
      def login_confirmation_matches?(login, login_confirmation)
        login.casecmp(login_confirmation) == 0
      end
    # :nocov:
    end

    def login_meets_length_requirements?(login)
      if login_minimum_length > login.length
        set_login_requirement_error_message(:login_too_short, login_too_short_message)
        false
      elsif login_maximum_length < login.length
        set_login_requirement_error_message(:login_too_long, login_too_long_message)
        false
      elsif login_maximum_bytes < login.bytesize
        set_login_requirement_error_message(:login_too_many_bytes, login_too_many_bytes_message)
        false
      else
        true
      end
    end

    def login_meets_email_requirements?(login)
      return true unless require_email_address_logins?
      return true if login_valid_email?(login)
      set_login_requirement_error_message(:login_not_valid_email, login_not_valid_email_message)
      return false
    end

    def login_valid_email?(login)
      login =~ login_email_regexp
    end

    def password_meets_length_requirements?(password)
      if password_minimum_length > password.length
        set_password_requirement_error_message(:password_too_short, password_too_short_message)
        false
      elsif password_maximum_length && password_maximum_length < password.length
        set_password_requirement_error_message(:password_too_long, password_too_long_message)
        false
      elsif password_maximum_bytes && password_maximum_bytes < password.bytesize
        set_password_requirement_error_message(:password_too_many_bytes, password_too_many_bytes_message)
        false
      else
        true
      end
    end

    def password_does_not_contain_null_byte?(password)
      return true unless password.include?("\0")
      set_password_requirement_error_message(:password_contains_null_byte, contains_null_byte_message)
      false
    end

    if ENV['RACK_ENV'] == 'test'
      def password_hash_cost
        BCrypt::Engine::MIN_COST
      end
    else
      # :nocov:
      def password_hash_cost
        BCrypt::Engine::DEFAULT_COST
      end
      # :nocov:
    end

    def extract_password_hash_cost(hash)
      hash[4, 2].to_i
    end
  end
end
