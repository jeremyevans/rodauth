# frozen-string-literal: true

module Rodauth
  Feature.define(:update_password_hash, :UpdatePasswordHash) do
    depends :login_password_requirements_base

    uses_instance_variables(:@current_password_hash_cost, :@update_password_hash)

    def password_match?(password)
      if (result = super) && update_password_hash?
        @update_password_hash = false
        set_password(password)
      end

      result
    end

    private

    def update_password_hash?
      password_hash_cost != @current_password_hash_cost || @update_password_hash
    end

    def get_password_hash
      if hash = super
        @current_password_hash_cost = extract_password_hash_cost(hash)
      end

      hash
    end
  end
end
