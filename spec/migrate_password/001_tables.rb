require 'rodauth/migrations'

Sequel.migration do
  up do
    # Used by the login and change password features
    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :password_hash, :null=>false
    end

    Rodauth.create_database_authentication_functions(self)
    Rodauth.set_database_authentication_function_permissions(self)
  end

  down do
    Rodauth.drop_database_authentication_functions(self)
    drop_table(:account_password_hashes)
  end
end
