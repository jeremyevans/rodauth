# frozen-string-literal: true

require 'argon2'

module Rodauth
  Feature.define(:argon2, :Argon2) do
    depends :login_password_requirements_base

    auth_value_method :password_hash_algorithm, nil

    private

    def password_hash_match?(hash, password)
      return argon_password_hash_match?(hash, password) unless password_hash_algorithm

      if argon_hash_algorithm?(hash)
        argon_password_hash_match?(hash, password)
      else
        super
      end
    end

    if ENV['RACK_ENV'] == 'test'
      def password_hash_cost
        if migrate_to_bcrypt?
          super
        else
          { t_cost: 1, m_cost: 3 }
        end
      end
    else
      # :nocov:
      def password_hash_cost
        if migrate_to_bcrypt?
          super
        else
          { t_cost: 2, m_cost: 16 }
        end
      end

      # :nocov:
    end

    def password_hash(password)
      if migrate_to_bcrypt?
        super
      else
        hasher = ::Argon2::Password.new(password_hash_cost)
        hasher.create(password)
      end
    end

    def hash_secret(password, salt)
      if argon_hash_algorithm?(salt)
        hasher = ::Argon2::Password.new(get_hash_params(salt))
        hasher.create(password)
      else
        super
      end
    end

    def get_hash_params(salt)
      original_salt = { salt_do_not_supply: Base64.decode64(salt.split('$').last) }

      get_password_hash_cost(salt).merge(original_salt)
    end

    def get_password_hash_cost(hash)
      if argon_hash_algorithm?(hash)
        cost_arg = hash.split('$')[3].scan(/\d+/).map(&:to_i)

        { t_cost: cost_arg[1], m_cost: Math.log2(cost_arg[0]).to_i }
      else
        super
      end
    end

    def argon_hash_algorithm?(hash)
      return false unless hash

      hash.split('$')[1] == 'argon2id'
    end

    def argon_password_hash_match?(hash, password)
      ::Argon2::Password.verify_password(password, hash)
    end

    def migrate_to_bcrypt?
      case password_hash_algorithm
      when 'bcrypt'
        true
      when 'argon2'
        false
      when nil
        false
      else
        raise ArgumentError, "invalid password_hash_algorithm it should be 'argon2' or 'bcrypt'"
      end
    end
  end
end
