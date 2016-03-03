require "rake"
require "rake/clean"

CLEAN.include ["rodauth-*.gem", "rdoc", "coverage"]

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
  sh "#{FileUtils::RUBY} spec/rodauth_spec.rb"
  env.each{|k,v| ENV.delete(k)}
end

desc "Run specs"
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
  ENV['RUBYOPT'] ? (ENV['RUBYOPT'] += " -w") : (ENV['RUBYOPT'] = '-w')
  rake = ENV['RAKE'] || "#{FileUtils::RUBY} -S rake"
  sh %{#{rake} 2>&1 | egrep -v \": warning: instance variable @.* not initialized|: warning: method redefined; discarding old|: warning: previous definition of|: warning: statement not reached"}
end

desc "Setup database used for testing"
task :db_setup do
  sh 'echo "CREATE USER rodauth_test PASSWORD \'rodauth_test\'" | psql -U postgres'
  sh 'echo "CREATE USER rodauth_test_password PASSWORD \'rodauth_test\'" | psql -U postgres'
  sh 'createdb -U postgres -O rodauth_test rodauth_test'
  sh 'echo "CREATE EXTENSION citext" | psql -U postgres rodauth_test'
  require 'sequel'
  Sequel.extension :migration
  Sequel.postgres(:user=>'rodauth_test', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate')
  end
  Sequel.postgres('rodauth_test', :user=>'rodauth_test_password', :password=>'rodauth_test') do |db|
    Sequel::Migrator.run(db, 'spec/migrate_password', :table=>'schema_info_password')
  end
end

desc "Teardown database used for testing"
task :db_teardown do
  sh 'dropdb -U postgres rodauth_test'
  sh 'dropuser -U postgres rodauth_test_password'
  sh 'dropuser -U postgres rodauth_test'
end
