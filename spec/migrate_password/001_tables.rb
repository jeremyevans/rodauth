Sequel.migration do
  up do
    # Used by the login and change password features
    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true, :type=>Bignum
      String :password_hash, :null=>false
    end

    # Function used to check if a password is valid.  Takes the related account id
    # and unencrypted password, checks if password matches password hash.
    run <<END
CREATE OR REPLACE FUNCTION account_valid_password(account_id int8, password text) RETURNS boolean AS $$
DECLARE valid boolean;
BEGIN
SELECT password_hash = crypt($2, password_hash) INTO valid 
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
    run "REVOKE ALL ON FUNCTION account_valid_password(int8, text) FROM public"
    run "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{app_user}"
    run "GRANT SELECT(id) ON account_password_hashes TO #{app_user}"
    run "GRANT EXECUTE ON FUNCTION account_valid_password(int8, text) TO #{app_user}"
  end

  down do
    run "DROP FUNCTION account_valid_password(int8, text)"
    drop_table(:account_password_hashes)
  end
end
