# frozen-string-literal: true

module Rodauth
  def self.create_database_authentication_functions(db, opts={})
    table_name = opts[:table_name] || :account_password_hashes
    get_salt_name = opts[:get_salt_name] || :rodauth_get_salt
    valid_hash_name = opts[:valid_hash_name] || :rodauth_valid_password_hash 

    case db.database_type
    when :postgres
      search_path = opts[:search_path] || 'public, pg_temp'
      primary_key_type =
        case db.schema(table_name).find { |row| row.first == :id }[1][:db_type]
        when 'uuid' then :uuid
        else :int8
        end

      db.run <<END
CREATE OR REPLACE FUNCTION #{get_salt_name}(acct_id #{primary_key_type}) RETURNS text AS $$
DECLARE salt text;
BEGIN
SELECT substr(password_hash, 0, 30) INTO salt 
FROM #{table_name}
WHERE acct_id = id;
RETURN salt;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = #{search_path};
END

      db.run <<END
CREATE OR REPLACE FUNCTION #{valid_hash_name}(acct_id #{primary_key_type}, hash text) RETURNS boolean AS $$
DECLARE valid boolean;
BEGIN
SELECT password_hash = hash INTO valid 
FROM #{table_name}
WHERE acct_id = id;
RETURN valid;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = #{search_path};
END
    when :mysql
      db.run <<END
CREATE FUNCTION #{get_salt_name}(acct_id int8) RETURNS varchar(255)
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
RETURN (SELECT substr(password_hash, 1, 30)
FROM #{table_name}
WHERE acct_id = id);
END;
END

      db.run <<END
CREATE FUNCTION #{valid_hash_name}(acct_id int8, hash varchar(255)) RETURNS tinyint(1)
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
DECLARE valid tinyint(1);
DECLARE csr CURSOR FOR 
SELECT password_hash = hash
FROM #{table_name}
WHERE acct_id = id;
OPEN csr;
FETCH csr INTO valid;
CLOSE csr;
RETURN valid;
END;
END
    when :mssql
      db.run <<END
CREATE FUNCTION #{get_salt_name}(@account_id bigint) RETURNS nvarchar(255)
WITH EXECUTE AS OWNER
AS
BEGIN
DECLARE @salt nvarchar(255);
SELECT @salt = substring(password_hash, 0, 30)
FROM #{table_name}
WHERE id = @account_id;
RETURN @salt;
END;
END

      db.run <<END
CREATE FUNCTION #{valid_hash_name}(@account_id bigint, @hash nvarchar(255)) RETURNS bit
WITH EXECUTE AS OWNER
AS
BEGIN
DECLARE @valid bit;
DECLARE @ph nvarchar(255);
SELECT @ph = password_hash
FROM #{table_name}
WHERE id = @account_id;
IF(@hash = @ph)
  SET @valid = 1;
ELSE
  SET @valid = 0
RETURN @valid;
END;
END
    end
  end

  def self.drop_database_authentication_functions(db, opts={})
    table_name = opts[:table_name] || :account_password_hashes
    get_salt_name = opts[:get_salt_name] || :rodauth_get_salt
    valid_hash_name = opts[:valid_hash_name] || :rodauth_valid_password_hash 

    case db.database_type
    when :postgres
      primary_key_type =
        case db.schema(table_name).find { |row| row.first == :id }[1][:db_type]
        when 'uuid' then :uuid
        else :int8
        end
      db.run "DROP FUNCTION #{get_salt_name}(#{primary_key_type})"
      db.run "DROP FUNCTION #{valid_hash_name}(#{primary_key_type}, text)"
    when :mysql, :mssql
      db.run "DROP FUNCTION #{get_salt_name}"
      db.run "DROP FUNCTION #{valid_hash_name}"
    end
  end

  def self.create_database_previous_password_check_functions(db, opts={})
    create_database_authentication_functions(db, {:table_name=>:account_previous_password_hashes, :get_salt_name=>:rodauth_get_previous_salt, :valid_hash_name=>:rodauth_previous_password_hash_match}.merge(opts))
  end

  def self.drop_database_previous_password_check_functions(db, opts={})
    drop_database_authentication_functions(db, {:table_name=>:account_previous_password_hashes, :get_salt_name=>:rodauth_get_previous_salt, :valid_hash_name=>:rodauth_previous_password_hash_match}.merge(opts))
  end
end
