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
    # Used by the create account, account verification,
    # and close account features.
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
      end
      index :email, :unique=>true, :where=>{:status_id=>[1, 2]}

      # Only for testing of account_password_hash_column, not recommended for new
      # applications
      String :ph
    end

    # Used by the password reset feature
    create_table(:account_password_reset_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      DateTime :deadline, :null=>false, :default=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :days=>1)
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
      DateTime :deadline, :null=>false, :default=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :days=>14)
    end

    # Used by the lockout feature
    create_table(:account_login_failures) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      Integer :number, :null=>false, :default=>1
    end
    create_table(:account_lockouts) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      DateTime :deadline, :null=>false, :default=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :days=>1)
    end

    if database_type == :postgres
      # Grant password user access to reference accounts
      pw_user = get{Sequel.lit('current_user')} + '_password'
      run "GRANT REFERENCES ON accounts TO #{pw_user}"
    end
  end

  down do
    drop_table(:account_lockouts, :account_login_failures, :account_remember_keys, :account_verification_keys, :account_password_reset_keys, :accounts, :account_statuses)
  end
end
