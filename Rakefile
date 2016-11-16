require "rake"
require "rake/clean"

CLEAN.include ["rodauth-*.gem", "rdoc", "coverage", "www/public/rdoc", "www/public/*.html"]

# Packaging

desc "Build rodauth gem"
task :package=>[:clean] do |p|
  sh %{#{FileUtils::RUBY} -S gem build rodauth.gemspec}
end

### RDoc

RDOC_DEFAULT_OPTS = ["--line-numbers", "--inline-source", '--title', 'Rodauth: Authentication and Account Management Framework for Rack Applications']

begin
  gem 'hanna-nouveau'
  RDOC_DEFAULT_OPTS.concat(['-f', 'hanna'])
rescue Gem::LoadError
end

rdoc_task_class = begin
  require "rdoc/task"
  RDoc::Task
rescue LoadError
  require "rake/rdoctask"
  Rake::RDocTask
end

RDOC_OPTS = RDOC_DEFAULT_OPTS + ['--main', 'README.rdoc']
RDOC_FILES = %w"README.rdoc CHANGELOG MIT-LICENSE lib/**/*.rb" + Dir["doc/*.rdoc"] + Dir['doc/release_notes/*.txt']

rdoc_task_class.new do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.options += RDOC_OPTS
  rdoc.rdoc_files.add RDOC_FILES
end

# Specs

desc "Run specs"
task :default=>:spec

spec = proc do |env|
  env.each{|k,v| ENV[k] = v}
  sh "#{FileUtils::RUBY} spec/all.rb"
  env.each{|k,v| ENV.delete(k)}
end

desc "Run specs on PostgreSQL"
task "spec" do
  spec.call({})
end

desc "Run specs with coverage"
task "spec_cov" do
  ENV['COVERAGE'] = '1'
  spec.call('COVERAGE'=>'1')
end
  
desc "Run specs with -w, some warnings filtered"
task "spec_w" do
  rubyopt = ENV['RUBYOPT']
  ENV['RUBYOPT'] = "#{rubyopt} -w"
  spec.call('WARNING'=>'1')
  ENV['RUBYOPT'] = rubyopt
end

desc "Setup database used for testing on PostgreSQL"
task :db_setup_postgres do
  sh 'psql -U postgres -c "CREATE USER rodauth_test PASSWORD \'rodauth_test\'"'
  sh 'psql -U postgres -c "CREATE USER rodauth_test_password PASSWORD \'rodauth_test\'"'
  sh 'createdb -U postgres -O rodauth_test rodauth_test'
  sh 'psql -U postgres -c "CREATE EXTENSION citext" rodauth_test'
  $: << 'lib'
  require 'sequel'
  Sequel.extension :migration
  Sequel.postgres(:user=>'rodauth_test', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
  end
  Sequel.postgres('rodauth_test', :user=>'rodauth_test_password', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate_password', :table=>'schema_info_password')
  end
end

desc "Teardown database used for testing on MySQL"
task :db_teardown_postgres do
  sh 'dropdb -U postgres rodauth_test'
  sh 'dropuser -U postgres rodauth_test_password'
  sh 'dropuser -U postgres rodauth_test'
end

desc "Setup database used for testing on MySQL"
task :db_setup_mysql do
  sh 'mysql --user=root -p mysql < spec/sql/mysql_setup.sql'
  $: << 'lib'
  require 'sequel'
  Sequel.extension :migration
  Sequel.mysql2('rodauth_test', :user=>'rodauth_test_password', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
  end
  Sequel.mysql2('rodauth_test', :user=>'rodauth_test_password', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate_password', :table=>'schema_info_password')
  end
end

desc "Teardown database used for testing on MySQL"
task :db_teardown_mysql do
  sh 'mysql --user=root -p mysql < spec/sql/mysql_teardown.sql'
end

desc "Setup database used for testing on Microsoft SQL Server"
task :db_setup_mssql do
  sh 'sqlcmd -E -e -b -r1 -i spec\\sql\\mssql_setup.sql'
  $: << 'lib'
  require 'sequel'
  Sequel.extension :migration
  Sequel.tinytds('rodauth_test', :user=>'rodauth_test_password', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
  end
  Sequel.tinytds('rodauth_test', :user=>'rodauth_test_password', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate_password', :table=>'schema_info_password')
  end
end

desc "Teardown database used for testing on Microsoft SQL Server"
task :db_teardown_mssql do
  sh 'sqlcmd -E -e -b -r1 -i spec\\sql\\mssql_teardown.sql'
end

desc "Run specs on MySQL"
task :spec_mysql do
  spec.call('RODAUTH_SPEC_DB'=>'mysql2://rodauth_test:rodauth_test@localhost/rodauth_test')
end

task :spec_travis do
  if defined?(RUBY_ENGINE) && RUBY_ENGINE == 'jruby'
    pg_db = 'jdbc:postgresql://localhost/rodauth_test?user=postgres'
    my_db = "jdbc:mysql://localhost/rodauth_test?user=root"
  else
    pg_db = 'postgres:///rodauth_test?user=postgres'
    my_db = "mysql2://localhost/rodauth_test?user=root"
  end
  sh 'psql -U postgres -c "CREATE EXTENSION citext" rodauth_test'
  spec.call('RODAUTH_SPEC_MIGRATE'=>'1', 'RODAUTH_SPEC_DB'=>pg_db)
  spec.call('RODAUTH_SPEC_MIGRATE'=>'1', 'RODAUTH_SPEC_DB'=>my_db)
end

desc "Run specs on SQLite"
task :spec_sqlite do
  spec_db = if defined?(RUBY_ENGINE) && RUBY_ENGINE == 'jruby'
    'jdbc:sqlite::memory:'
  else
    'sqlite:/'
  end
  spec.call('RODAUTH_SPEC_MIGRATE'=>'1', 'RODAUTH_SPEC_DB'=>spec_db)
end

### Website

rdoc_task_class.new(:website_rdoc) do |rdoc|
  rdoc.rdoc_dir = "www/public/rdoc"
  rdoc.options += RDOC_OPTS
  rdoc.rdoc_files.add RDOC_FILES
end

desc "Make local version of website"
task :website_base do
  sh %{#{FileUtils::RUBY} -I lib www/make_www.rb}
end

desc "Make local version of website, with rdoc"
task :website => [:website_base, :website_rdoc]

desc "Serve local version of website via rackup"
task :serve => :website do
  sh %{#{FileUtils::RUBY} -C www -S rackup}
end
