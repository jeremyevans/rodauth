require "rake"
require "rake/clean"

CLEAN.include ["rodauth-*.gem", "rdoc", "coverage"]

# Packaging

desc "Build rodauth gem"
task :package=>[:clean] do |p|
  sh %{#{FileUtils::RUBY} -S gem build rodauth.gemspec}
end

# Specs

desc "Run specs"
task :default=>:spec

desc "Run specs"
task :spec do
  sh "#{FileUtils::RUBY} spec/rodauth_spec.rb"
end

desc "Setup database used for testing"
task :db_setup do
  sh 'createuser -U postgres rodauth_test'
  sh 'createuser -U postgres rodauth_test_password'
  sh 'createdb -U postgres -O rodauth_test rodauth_test'
  sh 'echo "CREATE EXTENSION pgcrypto" | psql -U postgres rodauth_test'
  sh 'echo "CREATE EXTENSION citext" | psql -U postgres rodauth_test'
  require 'sequel'
  Sequel.extension :migration
  Sequel.postgres(:user=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
  end
  Sequel.postgres('rodauth_test', :user=>'rodauth_test_password') do |db|
    Sequel::Migrator.run(db, 'spec/migrate_password', :table=>'schema_info_password')
  end
end

desc "Teardown database used for testing"
task :db_teardown do
  sh 'dropdb -U postgres rodauth_test'
  sh 'dropuser -U postgres rodauth_test_password'
  sh 'dropuser -U postgres rodauth_test'
end
