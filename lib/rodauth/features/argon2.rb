# frozen-string-literal: true

require 'argon2'

# :nocov:
if !defined?(Argon2::VERSION) || Argon2::VERSION < '2'
  raise LoadError, "argon2 version 1.x not supported as it does not support argon2id hashes"
end
# :nocov:

module Rodauth
  Feature.define(:argon2, :Argon2) do
    depends :login_password_requirements_base

    auth_value_method :argon2_secret, nil
    auth_value_method :use_argon2?, true

    private

    if Argon2::VERSION != '2.1.0'
      def argon2_salt_option
        :salt_do_not_supply
      end
    # :nocov:
    else
      def argon2_salt_option
        :salt_for_testing_purposes_only
      end
    # :nocov:
    end

    def password_hash_cost
      return super unless use_argon2?
      argon2_hash_cost 
    end

    def password_hash(password)
      return super unless use_argon2?

      argon2_params = Hash[password_hash_cost]
      argon2_params[:secret] = argon2_secret
      ::Argon2::Password.new(argon2_params).create(password)
    end

    def password_hash_match?(hash, password)
      return super unless argon2_hash_algorithm?(hash)
      argon2_password_hash_match?(hash, password)
    end

    def password_hash_using_salt(password, salt)
      return super unless argon2_hash_algorithm?(salt)

      argon2_params = Hash[extract_password_hash_cost(salt)]
      argon2_params[argon2_salt_option] = Base64.decode64(salt.split('$').last)
      argon2_params[:secret] = argon2_secret
      ::Argon2::Password.new(argon2_params).create(password)
    end

    def extract_password_hash_cost(hash)
      return super unless argon2_hash_algorithm?(hash )

      /\A\$argon2id\$v=\d+\$m=(\d+),t=(\d+)/ =~ hash
      { t_cost: $2.to_i, m_cost: Math.log2($1.to_i).to_i }
    end

    if ENV['RACK_ENV'] == 'test'
      def argon2_hash_cost
        {t_cost: 1, m_cost: 3}
      end
    # :nocov:
    else
      def argon2_hash_cost
        {t_cost: 2, m_cost: 16}
      end
    end
    # :nocov:

    def argon2_hash_algorithm?(hash)
      hash.start_with?('$argon2id$')
    end

    def argon2_password_hash_match?(hash, password)
      ::Argon2::Password.verify_password(password, hash, argon2_secret)
    end
  end
end
