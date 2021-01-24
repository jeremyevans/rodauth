# frozen-string-literal: true

module Rodauth
  Feature.define(:update_password_hash, :UpdatePasswordHash) do
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
        @current_password_hash_cost = get_hash_cost(hash)
      end

      hash
    end

    def get_hash_cost(hash)
      case get_hash_algorithm(hash)
      when 'bcrypt'
        hash.split('$')[2].to_i
      when 'argon2'
        cost_arg = hash.split('$')[3].scan(/\d+/).map(&:to_i)

        { t_cost: cost_arg[1], m_cost: Math.log2(cost_arg[0]).to_i }
      end
    end
  end
end
