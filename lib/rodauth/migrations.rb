module Rodauth
  def self.supports_database_authentication_functions?(db)
    db.database_type == :postgres
  end

  def self.create_database_authentication_functions(db)
    case db.database_type
    when :postgres
      # Function that returns salt for current password.
      db.run <<END
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
      db.run <<END
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

  def self.drop_database_authentication_functions(db)
    case db.database_type
    when :postgres
      db.run "DROP FUNCTION rodauth_get_salt(int8)"
      db.run "DROP FUNCTION rodauth_valid_password_hash(int8, text)"
    end
  end

  def self.set_account_table_reference_permissions(db, opts={})
    case db.database_type
    when :postgres
      user = db.get{Sequel.lit('current_user')} + '_password'
      db.run "GRANT REFERENCES ON accounts TO #{user}"
    end
  end

  def self.set_database_authentication_function_permissions(db, opts={})
    case db.database_type
    when :postgres
      user = opts[:user] || db.get{Sequel.lit('current_user')}.sub(/_password\z/, '')
      db.run "REVOKE ALL ON account_password_hashes FROM public"
      db.run "REVOKE ALL ON FUNCTION rodauth_get_salt(int8) FROM public"
      db.run "REVOKE ALL ON FUNCTION rodauth_valid_password_hash(int8, text) FROM public"
      db.run "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{user}"
      db.run "GRANT SELECT(id) ON account_password_hashes TO #{user}"
      db.run "GRANT EXECUTE ON FUNCTION rodauth_get_salt(int8) TO #{user}"
      db.run "GRANT EXECUTE ON FUNCTION rodauth_valid_password_hash(int8, text) TO #{user}"
    end
  end
end
