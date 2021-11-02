require 'rodauth/migrations'

Sequel.migration do
  up do
    primary_key_type = ENV['RODAUTH_SPEC_UUID'] && database_type == :postgres ? :uuid : :bigint

    extension :date_arithmetic

    create_table(:account_statuses) do
      Integer :id, :primary_key=>true
      String :name, :null=>false, :unique=>true
    end
    from(:account_statuses).import([:id, :name], [[1, 'Unverified'], [2, 'Verified'], [3, 'Closed']])

    db = self
    create_table(:accounts) do
      if primary_key_type == :uuid
        uuid :id, :primary_key=>true, :default=>Sequel.function(:gen_random_uuid)
      else
        primary_key :id, :type=>:Bignum
      end
      foreign_key :status_id, :account_statuses, :null=>false, :default=>1
      if db.database_type == :postgres
        citext :email, :null=>false
        constraint :valid_email, :email=>/^[^,;@ \r\n]+@[^,@; \r\n]+\.[^,@; \r\n]+$/
      else
        String :email, :null=>false
      end
      if db.supports_partial_indexes?
        index :email, :unique=>true, :where=>{:status_id=>[1, 2]}
      else
        index :email, :unique=>true
      end

      String :ph
    end

    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :password_hash, :null=>false
    end
    Rodauth.create_database_authentication_functions(self, argon2: ENV['RODAUTH_NO_ARGON2'] != '1')

    deadline_opts = proc do |days|
      if database_type == :mysql
        {:null=>false}
      else
        {:null=>false, :default=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :days=>days)}
      end
    end

    json_type = case database_type
    when :postgres
      :jsonb
    when :sqlite
      :json
    else
      String
    end
    create_table(:account_authentication_audit_logs) do
      if primary_key_type == :uuid
        uuid :id, :primary_key=>true, :default=>Sequel.function(:gen_random_uuid)
      else
        primary_key :id, :type=>:Bignum
      end
      foreign_key :account_id, :accounts, :null=>false, :type=>primary_key_type
      DateTime :at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
      String :message, :null=>false
      column :metadata, json_type
      index [:account_id, :at], :name=>:audit_account_at_idx
      index :at, :name=>:audit_at_idx
    end

    create_table(:account_password_reset_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
      DateTime :email_last_sent, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_jwt_refresh_keys) do
      if primary_key_type == :uuid
        uuid :id, :primary_key=>true, :default=>Sequel.function(:gen_random_uuid)
      else
        primary_key :id, :type=>:Bignum
      end
      foreign_key :account_id, :accounts, :null=>false, :type=>primary_key_type
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
      index :account_id, :name=>:account_jwt_rk_account_id_idx
    end

    create_table(:account_verification_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
      DateTime :requested_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
      DateTime :email_last_sent, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_login_change_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
      String :login, :null=>false
      DateTime :deadline, deadline_opts[1]
    end

    create_table(:account_remember_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
      DateTime :deadline, deadline_opts[14]
    end

    create_table(:account_email_auth_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
      DateTime :email_last_sent, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_login_failures) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      Integer :number, :null=>false, :default=>1
    end
    create_table(:account_lockouts) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
      DateTime :deadline, deadline_opts[1]
      DateTime :email_last_sent
    end

    create_table(:account_password_change_times) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      DateTime :changed_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_activity_times) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      DateTime :last_activity_at, :null=>false
      DateTime :last_login_at, :null=>false
      DateTime :expired_at
    end

    create_table(:account_session_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
    end

    create_table(:account_active_session_keys) do
      foreign_key :account_id, :accounts, :type=>primary_key_type
      String :session_id
      Time :created_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
      Time :last_use, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
      primary_key [:account_id, :session_id]
    end

    create_table(:account_webauthn_user_ids) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :webauthn_id, :null=>false
    end
    create_table(:account_webauthn_keys) do
      foreign_key :account_id, :accounts, :type=>primary_key_type
      String :webauthn_id
      String :public_key, :null=>false
      Integer :sign_count, :null=>false
      Time :last_use, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
      primary_key [:account_id, :webauthn_id]
    end

    create_table(:account_otp_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :key, :null=>false
      Integer :num_failures, :null=>false, :default=>0
      Time :last_use, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_recovery_codes) do
      foreign_key :id, :accounts, :type=>primary_key_type
      String :code
      primary_key [:id, :code]
    end

    create_table(:account_sms_codes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>primary_key_type
      String :phone_number, :null=>false
      Integer :num_failures
      String :code
      DateTime :code_issued_at, :null=>false, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_previous_password_hashes) do
      primary_key :id, :type=>:Bignum
      foreign_key :account_id, :accounts, :type=>primary_key_type
      String :password_hash, :null=>false
    end
    Rodauth.create_database_previous_password_check_functions(self, argon2: ENV['RODAUTH_NO_ARGON2'] != '1')
  end
end
