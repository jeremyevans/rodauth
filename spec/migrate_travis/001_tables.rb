require 'rodauth/migrations'

Sequel.migration do
  up do
    extension :date_arithmetic

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

      String :ph
    end

    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :password_hash, :null=>false
    end
    Rodauth.create_database_authentication_functions(self)

    deadline_opts = proc do |days|
      if database_type == :mysql
        {:null=>false}
      else
        {:null=>false, :default=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :days=>days)}
      end
    end

    create_table(:account_password_reset_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
      DateTime :email_last_sent, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_verification_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :requested_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
      DateTime :email_last_sent, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_login_change_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      String :login, :null=>false
      DateTime :deadline, deadline_opts[1]
    end

    create_table(:account_remember_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[14]
    end

    create_table(:account_email_auth_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
      DateTime :email_last_sent, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_login_failures) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      Integer :number, :null=>false, :default=>1
    end
    create_table(:account_lockouts) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
      DateTime :email_last_sent
    end

    create_table(:account_password_change_times) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      DateTime :changed_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_activity_times) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      DateTime :last_activity_at, :null=>false
      DateTime :last_login_at, :null=>false
      DateTime :expired_at
    end

    create_table(:account_session_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
    end

    create_table(:account_otp_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :key, :null=>false
      Integer :num_failures, :null=>false, :default=>0
      Time :last_use, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_recovery_codes) do
      foreign_key :id, :accounts, :type=>:Bignum
      String :code
      primary_key [:id, :code]
    end

    create_table(:account_sms_codes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>:Bignum
      String :phone_number, :null=>false
      Integer :num_failures
      String :code
      DateTime :code_issued_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_previous_password_hashes) do
      primary_key :id, :type=>:Bignum
      foreign_key :account_id, :accounts, :type=>:Bignum
      String :password_hash, :null=>false
    end
    Rodauth.create_database_previous_password_check_functions(self)
  end
end
