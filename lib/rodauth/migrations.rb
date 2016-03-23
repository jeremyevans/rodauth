module Rodauth
  def self.supports_database_authentication_functions?(db)
    db.database_type == :postgres
  end

  def self.create_database_authentication_functions(db)
    case db.database_type
    when :postgres
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
    when :mysql
      db.run <<END
CREATE FUNCTION rodauth_get_salt(account_id int8) RETURNS varchar(255)
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
DECLARE salt varchar(255);
DECLARE csr CURSOR FOR
SELECT substr(password_hash, 1, 30)
FROM account_password_hashes
WHERE account_id = id;
OPEN csr;
FETCH csr INTO salt;
CLOSE csr;
RETURN salt;
END;
END

      db.run <<END
CREATE FUNCTION rodauth_valid_password_hash(account_id int8, hash varchar(255)) RETURNS boolean
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
DECLARE valid tinyint(1);
DECLARE csr CURSOR FOR 
SELECT password_hash = hash
FROM account_password_hashes
WHERE account_id = id;
OPEN csr;
FETCH csr INTO valid;
CLOSE csr;
RETURN valid;
END;
END
    end
  end

  def self.drop_database_authentication_functions(db)
    case db.database_type
    when :postgres, :mysql
      db.run "DROP FUNCTION rodauth_get_salt(int8)"
      db.run "DROP FUNCTION rodauth_valid_password_hash(int8, text)"
    end
  end
end
