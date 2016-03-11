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
      citext :email, :null=>false

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

    # Used by the login and change password features
    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :password_hash, :null=>false
    end

    if database_type == :postgres
      # Function that returns salt for current password.
      run <<END
CREATE OR REPLACE FUNCTION rodauth_get_salt(account_id int8) RETURNS text AS $$
DECLARE salt text;
BEGIN
SELECT substr(password_hash, 0, 30) INTO salt 
FROM account_password_hashes
WHERE account_id = id;
RETURN salt;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp;
END

      # Function that checks if password hash is valid for given user.
      run <<END
CREATE OR REPLACE FUNCTION rodauth_valid_password_hash(account_id int8, hash text) RETURNS boolean AS $$
DECLARE valid boolean;
BEGIN
SELECT password_hash = hash INTO valid 
FROM account_password_hashes
WHERE account_id = id;
RETURN valid;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp;
END
    end
  end

  down do
    run "DROP FUNCTION rodauth_get_salt(int8)"
    run "DROP FUNCTION rodauth_valid_password_hash(int8, text)"
    drop_table()
    drop_table(:account_password_hashes, :account_lockouts, :account_login_failures, :account_remember_keys, :account_verification_keys, :account_password_reset_keys, :accounts, :account_statuses)
  end
end
