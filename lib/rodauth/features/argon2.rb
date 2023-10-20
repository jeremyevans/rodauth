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

    auth_value_method :argon2_old_secret, nil
    auth_value_method :argon2_secret, nil
    auth_value_method :use_argon2?, true

    def password_hash(password)
      return super unless use_argon2?

      if secret = argon2_secret
        argon2_params = Hash[password_hash_cost]
        argon2_params[:secret] = secret
      else
        argon2_params = password_hash_cost
      end
      ::Argon2::Password.new(argon2_params).create(password)
    end

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

    def password_hash_match?(hash, password)
      return super unless argon2_hash_algorithm?(hash)
      argon2_password_hash_match?(hash, password)
    end

    def password_hash_using_salt(password, salt)
      return super unless argon2_hash_algorithm?(salt)
      argon2_password_hash_using_salt_and_secret(password, salt, argon2_secret)
    end

    def argon2_password_hash_using_salt_and_secret(password, salt, secret)
      argon2_params = Hash[extract_password_hash_cost(salt)]
      argon2_params[argon2_salt_option] = salt.split('$').last.unpack("m")[0]
      argon2_params[:secret] = secret
      ::Argon2::Password.new(argon2_params).create(password)
    end

    if Argon2::VERSION >= '2.1'
      def extract_password_hash_cost(hash)
        return super unless argon2_hash_algorithm?(hash)

        /\A\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)/ =~ hash
        { t_cost: $2.to_i, m_cost: Math.log2($1.to_i).to_i, p_cost: $3.to_i }
      end

      if ENV['RACK_ENV'] == 'test'
        def argon2_hash_cost
          { t_cost: 1, m_cost: 5, p_cost: 1 }
        end
      # :nocov:
      else
        def argon2_hash_cost
          { t_cost: 2, m_cost: 16, p_cost: 1 }
        end
      end
    else
      def extract_password_hash_cost(hash)
        return super unless argon2_hash_algorithm?(hash )

        /\A\$argon2id\$v=\d+\$m=(\d+),t=(\d+)/ =~ hash
        { t_cost: $2.to_i, m_cost: Math.log2($1.to_i).to_i }
      end

      if ENV['RACK_ENV'] == 'test'
        def argon2_hash_cost
          { t_cost: 1, m_cost: 5 }
        end
      else
        def argon2_hash_cost
          { t_cost: 2, m_cost: 16 }
        end
      end
    end
    # :nocov:

    def argon2_hash_algorithm?(hash)
      hash.start_with?('$argon2id$')
    end

    def argon2_password_hash_match?(hash, password)
      ret = ::Argon2::Password.verify_password(password, hash, argon2_secret)

      if ret == false && argon2_old_secret != argon2_secret && (ret = ::Argon2::Password.verify_password(password, hash, argon2_old_secret))
        @update_password_hash = true
      end

      ret
    end

    def database_function_password_match?(name, hash_id, password, salt)
      return true if super

      if use_argon2? && argon2_hash_algorithm?(salt) && argon2_old_secret != argon2_secret && (ret = db.get(Sequel.function(function_name(name), hash_id, argon2_password_hash_using_salt_and_secret(password, salt, argon2_old_secret))))
        @update_password_hash = true
      end

      !!ret
    end
  end
end
