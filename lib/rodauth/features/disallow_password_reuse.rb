# frozen-string-literal: true

module Rodauth
  Feature.define(:disallow_password_reuse, :DisallowPasswordReuse) do
    depends :login_password_requirements_base

    translatable_method :password_same_as_previous_password_message, "same as previous password"
    auth_value_method :previous_password_account_id_column, :account_id
    auth_value_method :previous_password_hash_column, :password_hash
    auth_value_method :previous_password_hash_table, :account_previous_password_hashes
    auth_value_method :previous_password_id_column, :id
    auth_value_method :previous_passwords_to_check, 6

    auth_methods(
      :add_previous_password_hash,
      :password_doesnt_match_previous_password?
    )

    def set_password(password)
      hash = super
      add_previous_password_hash(hash)
      hash
    end

    def add_previous_password_hash(hash) 
      ds = previous_password_ds

      unless @dont_check_previous_password
        keep_before = ds.reverse(previous_password_id_column).
          limit(nil, previous_passwords_to_check).
          get(previous_password_id_column)

        if keep_before
          ds.where(Sequel.expr(previous_password_id_column) <= keep_before).
            delete
        end
      end

      # This should never raise uniqueness violations, as it uses a serial primary key
      ds.insert(previous_password_account_id_column=>account_id, previous_password_hash_column=>hash)
    end

    def password_meets_requirements?(password)
      super &&
        (@dont_check_previous_password || password_doesnt_match_previous_password?(password))
    end

    private

    def password_doesnt_match_previous_password?(password)
      match = if use_database_authentication_functions?
        salts = previous_password_ds.
          select_map([previous_password_id_column, Sequel.function(function_name(:rodauth_get_previous_salt), previous_password_id_column).as(:salt)])
        return true if salts.empty?

        salts.any? do |hash_id, salt|
          database_function_password_match?(:rodauth_previous_password_hash_match, hash_id, password, salt)
        end
      else
        # :nocov:
        previous_password_ds.select_map(previous_password_hash_column).any? do |hash|
          password_hash_match?(hash, password)
        end
        # :nocov:
      end

      return true unless match
      set_password_requirement_error_message(:password_same_as_previous_password, password_same_as_previous_password_message)
      false
    end

    def after_close_account
      super if defined?(super)
      previous_password_ds.delete
    end

    def before_create_account_route
      super if defined?(super)
      @dont_check_previous_password = true
    end

    def before_verify_account_route
      super if defined?(super)
      @dont_check_previous_password = true
    end

    def after_create_account
      if account_password_hash_column && !(respond_to?(:verify_account_set_password?) && verify_account_set_password?)
        add_previous_password_hash(password_hash(param(password_param)))
      end
      super if defined?(super)
    end

    def previous_password_ds
      db[previous_password_hash_table].where(previous_password_account_id_column=>account_id)
    end
  end
end
