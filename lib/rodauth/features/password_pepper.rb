# frozen-string-literal: true

module Rodauth
  Feature.define(:password_pepper, :PasswordPepper) do
    depends :login_password_requirements_base

    auth_value_method :password_pepper, nil
    auth_value_method :previous_password_peppers, [""]
    auth_value_method :password_pepper_update?, true

    def password_match?(password)
      if (result = super) && @previous_pepper_matched && password_pepper_update?
        set_password(password)
      end

      result
    end

    def password_hash(password)
      super(password + password_pepper.to_s)
    end

    private

    def password_hash_match?(hash, password)
      return super if password_pepper.nil?

      return true if super(hash, password + password_pepper)

      @previous_pepper_matched = previous_password_peppers.any? do |pepper|
        super(hash, password + pepper)
      end
    end

    def database_function_password_match?(name, hash_id, password, salt)
      return super if password_pepper.nil?

      return true if super(name, hash_id, password + password_pepper, salt)

      @previous_pepper_matched = previous_password_peppers.any? do |pepper|
        super(name, hash_id, password + pepper, salt)
      end
    end
  end
end
