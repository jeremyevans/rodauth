# frozen-string-literal: true

module Rodauth
  UpdatePasswordHash = Feature.define(:update_password_hash) do
    depends :login_password_requirements_base

    def password_match?(password)
      if (result = super) && update_password_hash?
        set_password(password)
      end

      result
    end

    private

    def update_password_hash?
      password_hash_cost != @current_password_hash_cost
    end

    def get_password_hash
      if hash = super
        @current_password_hash_cost = hash.split('$')[2].to_i
      end

      hash
    end
  end
end
