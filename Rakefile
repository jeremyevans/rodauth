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

require "rdoc/task"

RDOC_OPTS = RDOC_DEFAULT_OPTS + ['--main', 'README.rdoc']
RDOC_FILES = %w"README.rdoc CHANGELOG doc/CHANGELOG.old MIT-LICENSE lib/**/*.rb" + Dir["doc/**/*.rdoc"] + Dir['doc/release_notes/*.txt']

RDoc::Task.new do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.options += RDOC_OPTS
  rdoc.rdoc_files.add RDOC_FILES
end

desc "Check configuration method documentation"
task :check_method_doc do
  docs = {}
  Dir["doc/*.rdoc"].sort.each do |f|
    meths = File.binread(f).split("\n").grep(/\A(\w+[!?]?(\([^\)]+\))?) :: /).map{|line| line.split(/( :: |\()/, 2)[0]}.sort
    docs[File.basename(f).sub(/\.rdoc\z/, '')] = meths unless meths.empty?
  end
  require './lib/rodauth'
  docs.each do |f, doc_meths|
    require "./lib/rodauth/features/#{f}"
    feature = Rodauth::FEATURES[f.to_sym]
    meths = (feature.auth_methods + feature.auth_value_methods + feature.auth_private_methods).map(&:to_s).sort
    unless (undocumented_meths = meths - doc_meths).empty?
      puts "#{f} undocumented methods: #{undocumented_meths.join(', ')}"
    end
    unless (bad_doc_meths = doc_meths - meths).empty?
      puts "#{f} documented methods that don't exist: #{bad_doc_meths.join(', ')}"
    end
  end
  puts "#{docs.values.flatten.length} total documented configuration methods"
end

# Specs

adapters = if RUBY_ENGINE == 'jruby'
  {:mysql=>'jdbc:mysql', :mssql=>'jdbc:jtds:sqlserver', :postgres=>'jdbc:postgresql'}
else
  {:mysql=>'mysql2', :mssql=>'tinytds', :postgres=>'postgres'}
end

desc "Run specs"
task :default=>:spec

spec = proc do |env|
  env.each{|k,v| ENV[k] = v}
  sh "#{FileUtils::RUBY} #{"-w" if RUBY_VERSION >= '3'} spec/all.rb"
  env.each{|k,v| ENV.delete(k)}
end

desc "Run specs on PostgreSQL"
task "spec" do
  spec.call({})
end

desc "Run specs with method visibility checking"
task "spec_vis" do
  spec.call('CHECK_METHOD_VISIBILITY'=>'1')
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
  sh 'psql -U postgres -c "CREATE EXTENSION pgcrypto" rodauth_test'
  $: << 'lib'
  require 'sequel'
  Sequel.extension :migration
  Sequel.connect("#{adapters[:postgres]}:///rodauth_test?user=rodauth_test&password=rodauth_test") do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
  end
  Sequel.connect("#{adapters[:postgres]}:///rodauth_test?user=rodauth_test_password&password=rodauth_test") do |db|
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
  Sequel.connect("#{adapters[:mysql]}:///rodauth_test?user=rodauth_test_password&password=rodauth_test") do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
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
  sep = ';' if RUBY_ENGINE == 'jruby'
  Sequel.connect("#{adapters[:mssql]}://localhost/rodauth_test#{sep || '?'}user=rodauth_test_password#{sep || '&'}password=Rodauth1.") do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
    Sequel::Migrator.run(db, 'spec/migrate_password', :table=>'schema_info_password')
  end
end

desc "Teardown database used for testing on Microsoft SQL Server"
task :db_teardown_mssql do
  sh 'sqlcmd -E -e -b -r1 -i spec\\sql\\mssql_teardown.sql'
end

desc "Run specs on MySQL"
task :spec_mysql do
  spec.call('RODAUTH_SPEC_DB'=>"#{adapters[:mysql]}://localhost/rodauth_test?user=rodauth_test&password=rodauth_test")
end

task :spec_ci do
  mysql_host = "localhost"
  pg_database = "rodauth_test" unless ENV["DEFAULT_DATABASE"]

  if ENV["MYSQL_ROOT_PASSWORD"]
    mysql_password = "&password=root"
    mysql_host= "127.0.0.1:3306"
  end

  if RUBY_ENGINE == 'jruby'
    pg_db = "jdbc:postgresql://localhost/#{pg_database}?user=postgres"
    my_db = "jdbc:mysql://#{mysql_host}/rodauth_test?user=root#{mysql_password}&useSSL=false&allowPublicKeyRetrieval=true"
  else
    pg_db = "postgres://localhost/#{pg_database}?user=postgres"
    my_db = "mysql2://#{mysql_host}/rodauth_test?user=root#{mysql_password}&useSSL=false"
  end

  sh "psql -U postgres -h localhost -c 'CREATE EXTENSION citext' #{pg_database}"
  sh "psql -U postgres -h localhost -c 'CREATE EXTENSION pgcrypto' #{pg_database}" if ENV['RODAUTH_SPEC_UUID']
  spec.call('RODAUTH_SPEC_MIGRATE'=>'1', 'RODAUTH_SPEC_DB'=>pg_db)

  if RUBY_VERSION >= '2.4'
    spec.call('RODAUTH_SPEC_MIGRATE'=>'1', 'RODAUTH_SPEC_DB'=>my_db)
    Rake::Task['spec_sqlite'].invoke
  end
end

desc "Run specs on SQLite"
task :spec_sqlite do
  conn_string = if RUBY_ENGINE == 'jruby'
    'jdbc:sqlite::memory:'
  else
    'sqlite:/'
  end
  spec.call('RODAUTH_SPEC_MIGRATE'=>'1', 'RODAUTH_SPEC_DB'=>conn_string)
end

### Website

RDoc::Task.new(:website_rdoc) do |rdoc|
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
