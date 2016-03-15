require 'rodauth/migrations'

Sequel.migration do
  up do
    extension :date_arithmetic

    # Used by the account verification and close account features
    create_table(:account_statuses) do
      Integer :id, :primary_key=>true
      String :name, :null=>false, :unique=>true
    end
    from(:account_statuses).import([:id, :name], [[1, 'Unverified'], [2, 'Verified'], [3, 'Closed']])

    db = self
    create_table(:accounts) do
      primary_key :id, :type=>Bignum
      foreign_key :status_id, :account_statuses, :null=>false, :default=>1
      if db.database_type == :postgres
        citext :email, :null=>false
      else
        String :email, :null=>false
      end

      if db.database_type == :postgres
        constraint :valid_email, :email=>/^[^,;@ \r\n]+@[^,@; \r\n]+\.[^,@; \r\n]+$/
        index :email, :unique=>true, :where=>{:status_id=>[1, 2]}
      end

      # Only for testing of account_password_hash_column, not recommended for new
      # applications
      String :ph
    end

    deadline_opts = proc do |days|
      if database_type == :mysql
        {:null=>false}
      else
        {:null=>false, :default=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :days=>days)}
      end
    end

    # Used by the password reset feature
    create_table(:account_password_reset_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
    end

    # Used by the account verification feature
    create_table(:account_verification_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
    end

    # Used by the remember me feature
    create_table(:account_remember_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[14]
    end

    # Used by the lockout feature
    create_table(:account_login_failures) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      Integer :number, :null=>false, :default=>1
    end
    create_table(:account_lockouts) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
    end

    # Used by the login and change password features
    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :password_hash, :null=>false
    end

    Rodauth.create_database_authentication_functions(self)
  end

  down do
    Rodauth.drop_database_authentication_functions(self)
    drop_table(:account_password_hashes, :account_lockouts, :account_login_failures, :account_remember_keys, :account_verification_keys, :account_password_reset_keys, :accounts, :account_statuses)
  end
end
