Sequel.migration do
  up do
    # Used by the login and change password features
    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :password_hash, :null=>false
    end

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

    # Restrict access to the password hash table
    app_user = get{Sequel.lit('current_user')}.sub(/_password\z/, '')
    run "REVOKE ALL ON account_password_hashes FROM public"
    run "REVOKE ALL ON FUNCTION rodauth_get_salt(int8) FROM public"
    run "REVOKE ALL ON FUNCTION rodauth_valid_password_hash(int8, text) FROM public"
    run "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{app_user}"
    run "GRANT SELECT(id) ON account_password_hashes TO #{app_user}"
    run "GRANT EXECUTE ON FUNCTION rodauth_get_salt(int8) TO #{app_user}"
    run "GRANT EXECUTE ON FUNCTION rodauth_valid_password_hash(int8, text) TO #{app_user}"
  end

  down do
    run "DROP FUNCTION rodauth_get_salt(int8)"
    run "DROP FUNCTION rodauth_valid_password_hash(int8, text)"
    drop_table(:account_password_hashes)
  end
end
