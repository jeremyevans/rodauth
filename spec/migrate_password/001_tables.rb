require 'rodauth/migrations'

Sequel.migration do
  up do
    # Used by the login and change password features
    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :password_hash, :null=>false
    end

    Rodauth.create_database_authentication_functions(self)

    case database_type
    when :postgres
      user = get{Sequel.lit('current_user')}.sub(/_password\z/, '')
      run "REVOKE ALL ON account_password_hashes FROM public"
      run "REVOKE ALL ON FUNCTION rodauth_get_salt(int8) FROM public"
      run "REVOKE ALL ON FUNCTION rodauth_valid_password_hash(int8, text) FROM public"
      run "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{user}"
      run "GRANT SELECT(id) ON account_password_hashes TO #{user}"
      run "GRANT EXECUTE ON FUNCTION rodauth_get_salt(int8) TO #{user}"
      run "GRANT EXECUTE ON FUNCTION rodauth_valid_password_hash(int8, text) TO #{user}"
    when :mysql
      user = get{Sequel.lit('current_user')}.sub(/_password@/, '@')
      db_name = get{database{}}
      run "GRANT EXECUTE ON #{db_name}.* TO #{user}"
      run "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{user}"
      run "GRANT SELECT (id) ON account_password_hashes TO #{user}"
    when :mssql
      user = get{DB_NAME{}}
      run "GRANT EXECUTE ON rodauth_get_salt TO #{user}"
      run "GRANT EXECUTE ON rodauth_valid_password_hash TO #{user}"
      run "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{user}"
      run "GRANT SELECT ON account_password_hashes(id) TO #{user}"
    end
  end

  down do
    Rodauth.drop_database_authentication_functions(self)
    drop_table(:account_password_hashes)
  end
end
