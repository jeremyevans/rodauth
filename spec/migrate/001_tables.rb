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
      primary_key :id, :type=>:Bignum
      foreign_key :status_id, :account_statuses, :null=>false, :default=>1
      if db.database_type == :postgres
        citext :email, :null=>false
        constraint :valid_email, :email=>/^[^,;@ \r\n]+@[^,@; \r\n]+\.[^,@; \r\n]+$/
        index :email, :unique=>true, :where=>{:status_id=>[1, 2]}
      else
        String :email, :null=>false
        index :email, :unique=>true
      end
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
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
    end

    # Used by the refresh token feature
    create_table(:account_refresh_tokens) do
      primary_key :id, :type=>:Bignum
      foreign_key :account_id, :accounts, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
    end

    # Used by the account verification feature
    create_table(:account_verification_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :requested_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    # Used by the remember me feature
    create_table(:account_remember_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[14]
    end

    # Used by the lockout feature
    create_table(:account_login_failures) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      Integer :number, :null=>false, :default=>1
    end
    create_table(:account_lockouts) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
    end

    # Used by the password expiration feature
    create_table(:account_password_change_times) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      DateTime :changed_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    # Used by the account expiration feature
    create_table(:account_activity_times) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      DateTime :last_activity_at, :null=>false
      DateTime :last_login_at, :null=>false
      DateTime :expired_at
    end

    # Used by the single session feature
    create_table(:account_session_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
    end

    # Used by the otp feature
    create_table(:account_otp_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      Integer :num_failures, :null=>false, :default=>0
      Time :last_use, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    # Used by the recovery codes feature
    create_table(:account_recovery_codes) do
      foreign_key :id, :accounts, :type=>:Bignum
      String :code
      primary_key [:id, :code]
    end

    # Used by the sms codes feature
    create_table(:account_sms_codes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :phone_number, :null=>false
      Integer :num_failures
      String :code
      DateTime :code_issued_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    case database_type
    when :postgres
      user = get{Sequel.lit('current_user')} + '_password'
      run "GRANT REFERENCES ON accounts TO #{user}"
    when :mysql, :mssql
      user = if database_type == :mysql
        get{Sequel.lit('current_user')}.sub(/_password@/, '@')
      else
        get{DB_NAME{}}
      end
      run "GRANT ALL ON account_statuses TO #{user}"
      run "GRANT ALL ON accounts TO #{user}"
      run "GRANT ALL ON account_password_reset_keys TO #{user}"
      run "GRANT ALL ON account_verification_keys TO #{user}"
      run "GRANT ALL ON account_remember_keys TO #{user}"
      run "GRANT ALL ON account_login_failures TO #{user}"
      run "GRANT ALL ON account_lockouts TO #{user}"
      run "GRANT ALL ON account_password_change_times TO #{user}"
      run "GRANT ALL ON account_activity_times TO #{user}"
      run "GRANT ALL ON account_session_keys TO #{user}"
      run "GRANT ALL ON account_otp_keys TO #{user}"
      run "GRANT ALL ON account_recovery_codes TO #{user}"
      run "GRANT ALL ON account_sms_codes TO #{user}"
    end
  end

  down do
    drop_table(:account_sms_codes,
               :account_recovery_codes,
               :account_otp_keys,
               :account_session_keys,
               :account_activity_times,
               :account_password_change_times,
               :account_lockouts,
               :account_login_failures,
               :account_remember_keys,
               :account_verification_keys,
               :account_password_reset_keys,
               :accounts,
               :account_statuses)
  end
end
