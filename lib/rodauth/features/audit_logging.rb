# frozen-string-literal: true

module Rodauth
  Feature.define(:audit_logging, :AuditLogging) do
    auth_value_method :audit_logging_account_id_column, :account_id
    auth_value_method :audit_logging_message_column, :message
    auth_value_method :audit_logging_metadata_column, :metadata
    auth_value_method :audit_logging_table, :account_authentication_audit_logs
    auth_value_method :audit_log_metadata_default, nil

    auth_methods(
      :add_audit_log,
      :audit_log_insert_hash,
      :audit_log_message,
      :audit_log_message_default,
      :audit_log_metadata,
      :serialize_audit_log_metadata,
    )

    configuration_module_eval do
      [:audit_log_message_for, :audit_log_metadata_for].each do |method|
        define_method(method) do |action, value=nil, &block|
          block ||= proc{value}
          meth = :"#{method}_#{action}"
          @auth.send(:define_method, meth, &block)
          @auth.send(:private, meth)
        end
      end
    end

    def hook_action(hook_type, action)
      super
      # In after_logout, session is already cleared, so use before_logout in that case
      if (hook_type == :after || action == :logout) && (id = account ? account_id : session_value)
        add_audit_log(id, action)
      end
    end

    def add_audit_log(account_id, action)
      if hash = audit_log_insert_hash(account_id, action)
        audit_log_ds.insert(hash)
      end
    end

    def audit_log_insert_hash(account_id, action)
      if message = audit_log_message(action)
        {
          audit_logging_account_id_column => account_id,
          audit_logging_message_column => message,
          audit_logging_metadata_column => serialize_audit_log_metadata(audit_log_metadata(action))
        }
      end
    end

    def serialize_audit_log_metadata(metadata)
      metadata.to_json unless metadata.nil?
    end

    def audit_log_message_default(action)
      action.to_s
    end

    def audit_log_message(action)
      meth = :"audit_log_message_for_#{action}"
      if respond_to?(meth, true)
        send(meth)
      else
        audit_log_message_default(action)
      end
    end

    def audit_log_metadata(action)
      meth = :"audit_log_metadata_for_#{action}"
      if respond_to?(meth, true)
        send(meth)
      else
        audit_log_metadata_default
      end
    end

    private

    def audit_log_ds
      ds = db[audit_logging_table]
      # :nocov:
      if db.database_type == :postgres
      # :nocov:
        # For PostgreSQL, use RETURNING NULL. This allows the feature
        # to be used with INSERT but not SELECT permissions on the
        # table, useful for audit logging where the database user
        # the application is running as should not need to read the
        # logs.
        ds = ds.returning(nil)
      end
      ds
    end
  end
end
