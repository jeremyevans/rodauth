Sequel.migration do
  change do
    extension :date_arithmetic

    # Used by the otp feature
    create_table(:account_otp_keys) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :key, :null=>false
      Time :last_use
    end

    create_table(:account_otp_recovery_codes) do
      foreign_key :id, :accounts, :type=>Bignum
      String :code, :null=>false
      
      primary_key [:id, :code]
    end

    until_opts = if database_type == :mysql
      {:null=>false}
    else
      {:null=>false, :default=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :minutes=>1)}
    end

    create_table(:account_otp_auth_failures) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      Integer :number, :null=>false, :default=>1
    end
  end
end
