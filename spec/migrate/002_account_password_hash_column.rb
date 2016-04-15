Sequel.migration do
  up do
    # Only for testing of account_password_hash_column, not recommended for new
    # applications
    add_column :accounts, :ph, String
  end

  down do
    drop_column :accounts, :ph
  end
end
