require_relative 'spec_helper'

describe 'path_class_methods feature' do
  it "should add *_path and *_url methods as class methods" do
    rodauth do
      prefix '/foo'
      base_url 'https://foo.example.com'
      enable :path_class_methods, :login, :logout
    end
    roda do |r|
    end

    app.rodauth.login_path.must_equal '/foo/login'
    app.rodauth.logout_url.must_equal 'https://foo.example.com/foo/logout'

    app.rodauth.logout_path('bar'=>'baz').must_equal '/foo/logout?bar=baz'
    app.rodauth.login_url('bar'=>'baz').must_equal 'https://foo.example.com/foo/login?bar=baz'
  end

  it "*_path should work without base_url" do
    rodauth do
      enable :path_class_methods, :login, :logout
    end
    roda do |r|
    end

    app.rodauth.logout_path.must_equal '/logout'

    proc{app.rodauth.login_url}.must_raise NoMethodError
  end
end
