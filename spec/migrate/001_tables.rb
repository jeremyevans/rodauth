Sequel.migration do
  up do
    # Used by the account verification and close account features
    create_table(:account_statuses) do
      Integer :id, :primary_key=>true
      String :name, :null=>false, :unique=>true
    end
    from(:account_statuses).import([:id, :name], [[1, 'Unverified'], [2, 'Verified'], [3, 'Closed']])

    # Used by the create account, account verification,
    # and close account features.
    create_table(:accounts) do
      primary_key :id, :type=>Bignum
      foreign_key :status_id, :account_statuses, :null=>false, :default=>1
      citext :email, :null=>false

      constraint :valid_email, :email=>/^[^,;@ \r\n]+@[^,@; \r\n]+\.[^,@; \r\n]+$/
      index :email, :unique=>true, :where=>{:status_id=>[1, 2]}
    end

    # Used by the password reset feature
    create_table(:account_password_reset_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      DateTime :deadline, :null=>false, :default=>Sequel.lit("CURRENT_TIMESTAMP + '1 day'")
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
      DateTime :deadline, :null=>false, :default=>Sequel.lit("CURRENT_TIMESTAMP + '2 weeks'")
    end

    # Used by the lockout feature
    create_table(:account_login_failures) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      Integer :number, :null=>false, :default=>1
    end
    create_table(:account_lockouts) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      DateTime :deadline, :null=>false, :default=>Sequel.lit("CURRENT_TIMESTAMP + '1 day'")
    end

    # Grant password user access to reference accounts
    pw_user = get{Sequel.lit('current_user')} + '_password'
    run "GRANT REFERENCES ON accounts TO #{pw_user}"
  end

  down do
    drop_table(:account_verification_keys, :account_password_reset_keys, :accounts, :account_statuses)
  end
end
